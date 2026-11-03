package server

import (
	"context"
	"encoding/json"
	"errors"
	"runnerfleet/internal/capacity"
	"runnerfleet/internal/security"
	"runnerfleet/internal/spot"
	"runnerfleet/internal/store"
	"strings"
	"time"
)

const spotLaunchLifetime = 2 * time.Hour

type spotLaunch struct {
	ID, Pool, Market, InstanceType, SubnetID, ClientToken, EnrollmentHash string
	State, InstanceID, MachineID, Error                                   string
	PoolSnapshot                                                          string
	Architecture                                                          string
	CPU                                                                   float64
	MemoryMB                                                              int64
	Attempts                                                              int
	Next, Created, Updated                                                int64
}

func (s *Server) spotProvider(ctx context.Context, region string) (*spot.Provider, error) {
	s.spotMu.Lock()
	defer s.spotMu.Unlock()
	if provider := s.spotProviders[region]; provider != nil {
		return provider, nil
	}
	provider, err := spot.NewDefault(ctx, region)
	if err != nil {
		return nil, err
	}
	s.spotProviders[region] = provider
	return provider, nil
}

func (s *Server) reconcileSpot(ctx context.Context) {
	for _, pool := range s.pools() {
		if pool.Spot == nil {
			continue
		}
		want := 0
		if pool.Enabled {
			want = pool.Min
		}
		jobs, _ := s.Store.List("job")
		queued := 0
		for _, raw := range jobs {
			if !pool.Enabled {
				break
			}
			var job map[string]any
			if json.Unmarshal(raw, &job) != nil || text(job["status"]) != "queued" || number(job["installation"]) != pool.Installation {
				continue
			}
			repository := text(job["repository"])
			if pool.Target != repository && !(pool.Scope == "org" && strings.HasPrefix(repository, pool.Target+"/")) {
				continue
			}
			labels := []string{}
			if values, ok := job["labels"].([]any); ok {
				for _, value := range values {
					labels = append(labels, text(value))
				}
			}
			if capacity.Match(pool.Labels, labels) {
				queued++
			}
		}
		busy := 0
		for _, instance := range allInstances(s.Store) {
			if !pool.Enabled {
				break
			}
			if instance.Pool == pool.ID && instance.State == "busy" {
				busy++
			}
		}
		want = min(pool.Max, max(want, busy+queued))
		orgMax := 8
		var settings map[string]any
		_ = json.Unmarshal([]byte(s.Store.Get("settings")), &settings)
		if configured := number(settings["org_max_slots"]); configured > 0 {
			orgMax = int(configured)
		}
		want = min(want, orgMax)
		staticSlots := 0
		staticIDs := make(map[string]bool, len(pool.Machines))
		for _, id := range pool.Machines {
			staticIDs[id] = true
		}
		now := time.Now()
		for _, machine := range allMachines(s.Store) {
			if !pool.Enabled {
				break
			}
			if staticIDs[machine.ID] && machineSchedulable(machine, pool, now) {
				staticSlots += machinePoolSlots(machine, pool)
			}
		}
		neededSlots := max(0, want-staticSlots)
		cloudSlots := 0
		for _, machine := range allMachines(s.Store) {
			if machine.ProviderPool == pool.ID && machine.CloudProvider == "aws" && machine.State != "revoked" && machine.State != "terminated" && machine.State != "terminating" && machine.InterruptingAt == 0 {
				cloudSlots += machinePoolSlots(machine, pool)
			}
		}
		var pending int
		if err := s.Store.DB.QueryRow(`SELECT COUNT(*) FROM spot_launches WHERE pool=? AND (state IN ('pending','launching','running') OR state='failed' AND next>?)`, pool.ID, now.Unix()).Scan(&pending); err != nil {
			continue
		}
		reservedSlots := cloudSlots + pending*pool.Spot.SlotsPerMachine
		missingSlots := max(0, neededSlots-reservedSlots)
		missingMachines := (missingSlots + pool.Spot.SlotsPerMachine - 1) / pool.Spot.SlotsPerMachine
		launchesAllowed := max(0, pool.Spot.MaxMachines-countCloudMachines(s.Store, pool.ID)-pending)
		launchCount := min(missingMachines, launchesAllowed)
		for missing := launchCount; pool.Enabled && missing > 0; missing-- {
			if err := s.createSpotLaunch(pool); err != nil {
				s.alert("spot-launch-create:"+pool.ID, "Falha ao preparar worker Spot", "Não foi possível persistir um lançamento para o pool.")
				break
			}
		}
		if err := s.processSpotLaunches(ctx, pool); err != nil {
			s.alert("spot-launch:"+pool.ID, "Falha ao provisionar worker EC2", safeSpotError(err))
		}
		s.scaleInSpot(ctx, pool, neededSlots)
	}
}

func machineSchedulable(machine capacity.Machine, pool capacity.Pool, now time.Time) bool {
	if machine.State != "online" || machine.Arch != pool.Arch || now.Unix()-machine.LastSeen > 45 {
		return false
	}
	readyKey := "ready"
	enforcementKey := "enforcement"
	if pool.Execution == "service" {
		readyKey = "service_ready"
		enforcementKey = "service_enforcement"
	}
	if ready, _ := machine.Doctor[readyKey].(bool); !ready {
		return false
	}
	if machine.Shared {
		if enforcement, _ := machine.Doctor[enforcementKey].(bool); !enforcement {
			return false
		}
	}
	if machine.StartHour != machine.EndHour {
		zone, err := time.LoadLocation(machine.Timezone)
		if err != nil {
			return false
		}
		hour := now.In(zone).Hour()
		allowed := hour >= machine.StartHour && hour < machine.EndHour
		if machine.StartHour > machine.EndHour {
			allowed = hour >= machine.StartHour || hour < machine.EndHour
		}
		if !allowed {
			return false
		}
	}
	return true
}

func machinePoolSlots(machine capacity.Machine, pool capacity.Pool) int {
	if pool.CPU <= 0 || pool.MemoryMB <= 0 || pool.DiskMB <= 0 {
		return 0
	}
	cpuSlots := int(machine.CPU / pool.CPU)
	memorySlots := int(machine.MemoryMB / pool.MemoryMB)
	diskSlots := int64(machine.DiskMB) / pool.DiskMB
	return max(0, min(machine.MaxSlots, min(cpuSlots, min(memorySlots, int(diskSlots)))))
}

func countCloudMachines(s *store.Store, poolID string) int {
	count := 0
	for _, machine := range allMachines(s) {
		if machine.ProviderPool == poolID && machine.CloudProvider == "aws" && machine.State != "revoked" && machine.State != "terminated" {
			count++
		}
	}
	return count
}

func eligibleMachines(s *store.Store, pool capacity.Pool) []capacity.Machine {
	allowed := make(map[string]bool, len(pool.Machines))
	for _, id := range pool.Machines {
		allowed[id] = true
	}
	machines := []capacity.Machine{}
	for _, machine := range allMachines(s) {
		if allowed[machine.ID] || machine.CloudProvider == "aws" && machine.ProviderPool == pool.ID {
			machines = append(machines, machine)
		}
	}
	return machines
}

func drainOnce(s *store.Store, machineID, instanceID string) {
	var existing int
	err := s.DB.QueryRow(`SELECT COUNT(*) FROM commands WHERE machine=? AND kind='drain' AND state='pending' AND json_extract(data,'$.instance')=?`, machineID, instanceID).Scan(&existing)
	if err == nil && existing == 0 {
		_, _ = capacity.Command(s, machineID, "drain", map[string]any{"instance": instanceID})
	}
}

func (s *Server) createSpotLaunch(pool capacity.Pool) error {
	if pool.Spot == nil || len(pool.Spot.SubnetIDs) == 0 || len(pool.Spot.SpotInstanceTypes) == 0 {
		return errors.New("Spot pool is missing capacity options")
	}
	launchID := security.Random(16)
	code := security.Random(32)
	now := time.Now().Unix()
	clientToken := security.Random(32)
	subnet := pool.Spot.SubnetIDs[int(launchID[0])%len(pool.Spot.SubnetIDs)]
	instanceType := pool.Spot.SpotInstanceTypes[int(launchID[1])%len(pool.Spot.SpotInstanceTypes)]
	tx, err := s.Store.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	encrypted, err := security.Seal(s.Key, []byte(code))
	if err != nil {
		return err
	}
	if _, err = tx.Exec(`INSERT INTO kv(key,value) VALUES(?,?)`, "spot-enrollment:"+security.Hash(code), encrypted); err != nil {
		return err
	}
	if _, err = tx.Exec(`INSERT INTO enrollment(hash,expires) VALUES(?,?)`, security.Hash(code), now+int64(spotLaunchLifetime.Seconds())); err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT INTO spot_launches(id,pool,pool_snapshot,market,instance_type,subnet_id,client_token,enrollment_hash,state,next,created,updated) VALUES(?,?,?,'spot',?,?,?,?, 'pending',?,?,?)`, launchID, pool.ID, store.JSON(pool), instanceType, subnet, clientToken, security.Hash(code), now, now, now)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Server) processSpotLaunches(ctx context.Context, pool capacity.Pool) error {
	rows, err := s.Store.DB.Query(`SELECT id,pool,pool_snapshot,market,instance_type,subnet_id,client_token,enrollment_hash,state,instance_id,machine_id,cpu,memory_mb,architecture,attempts,next,error,created,updated FROM spot_launches WHERE pool=? AND state IN ('pending','launching','running','enrolled','terminating') AND next<=? ORDER BY created LIMIT 1`, pool.ID, time.Now().Unix())
	if err != nil {
		return err
	}
	launches := []spotLaunch{}
	for rows.Next() {
		var launch spotLaunch
		if err = rows.Scan(&launch.ID, &launch.Pool, &launch.PoolSnapshot, &launch.Market, &launch.InstanceType, &launch.SubnetID, &launch.ClientToken, &launch.EnrollmentHash, &launch.State, &launch.InstanceID, &launch.MachineID, &launch.CPU, &launch.MemoryMB, &launch.Architecture, &launch.Attempts, &launch.Next, &launch.Error, &launch.Created, &launch.Updated); err != nil {
			rows.Close()
			return err
		}
		launches = append(launches, launch)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, launch := range launches {
		launchPool := capacity.Pool{}
		if json.Unmarshal([]byte(launch.PoolSnapshot), &launchPool) != nil || launchPool.Spot == nil {
			s.Store.DB.Exec(`UPDATE spot_launches SET state='failed',error='invalid persisted pool snapshot',updated=? WHERE id=?`, time.Now().Unix(), launch.ID)
			invalidateSpotEnrollment(s.Store, launch.EnrollmentHash)
			continue
		}
		spotConfig := launchPool.Spot
		provider, err := s.spotProvider(ctx, spotConfig.Region)
		if err != nil {
			return err
		}
		lookupCtx, cancelLookup := context.WithTimeout(ctx, 15*time.Second)
		instances, findErr := provider.FindByLaunchID(lookupCtx, launch.ID)
		cancelLookup()
		if findErr != nil {
			s.Store.DB.Exec(`UPDATE spot_launches SET attempts=attempts+1,next=?,error=?,updated=? WHERE id=?`, time.Now().Add(30*time.Second).Unix(), safeSpotError(findErr), time.Now().Unix(), launch.ID)
			continue
		}
		if !pool.Enabled && launch.MachineID == "" {
			terminated := false
			for _, instance := range instances {
				if instance.State == "terminated" {
					continue
				}
				terminateCtx, cancelTerminate := context.WithTimeout(ctx, 15*time.Second)
				err = provider.Terminate(terminateCtx, instance.ID)
				cancelTerminate()
				if err != nil {
					s.Store.DB.Exec(`UPDATE spot_launches SET next=?,error=?,updated=? WHERE id=?`, time.Now().Add(30*time.Second).Unix(), safeSpotError(err), time.Now().Unix(), launch.ID)
				} else {
					s.Store.DB.Exec(`UPDATE spot_launches SET state='terminating',instance_id=?,next=?,error='pool disabled',updated=? WHERE id=?`, instance.ID, time.Now().Add(30*time.Second).Unix(), time.Now().Unix(), launch.ID)
				}
				terminated = true
				break
			}
			if !terminated {
				s.Store.DB.Exec(`UPDATE spot_launches SET state='failed',next=?,error='pool disabled',updated=? WHERE id=?`, time.Now().Unix(), time.Now().Unix(), launch.ID)
			}
			invalidateSpotEnrollment(s.Store, launch.EnrollmentHash)
			continue
		}
		if len(instances) == 0 && launch.MachineID != "" && launch.InstanceID != "" {
			lookupIDCtx, cancelLookupID := context.WithTimeout(ctx, 15*time.Second)
			byID, byIDErr := provider.FindByInstanceID(lookupIDCtx, launch.InstanceID)
			cancelLookupID()
			if byIDErr != nil {
				s.Store.DB.Exec(`UPDATE spot_launches SET next=?,error=?,updated=? WHERE id=?`, time.Now().Add(30*time.Second).Unix(), safeSpotError(byIDErr), time.Now().Unix(), launch.ID)
				continue
			}
			if len(byID) == 0 || byID[0].State == "terminated" {
				s.Store.DB.Exec(`UPDATE spot_launches SET state='terminated',next=?,updated=? WHERE id=?`, time.Now().Unix(), time.Now().Unix(), launch.ID)
				markSpotMachineTerminated(s.Store, launch.MachineID)
				continue
			}
			if byID[0].State == "shutting-down" {
				s.Store.DB.Exec(`UPDATE spot_launches SET state='terminating',next=?,updated=? WHERE id=?`, time.Now().Unix()+30, time.Now().Unix(), launch.ID)
				var machine capacity.Machine
				if s.Store.Read("machine", launch.MachineID, &machine) == nil {
					machine.State = "terminating"
					_ = s.Store.Put("machine", machine.ID, machine)
				}
				continue
			}
			s.Store.DB.Exec(`UPDATE spot_launches SET state='enrolled',next=?,updated=? WHERE id=?`, time.Now().Unix()+30, time.Now().Unix(), launch.ID)
			continue
		}
		if launch.MachineID == "" && launch.State != "terminating" && time.Since(time.Unix(launch.Created, 0)) >= spotLaunchLifetime {
			terminated := false
			for _, instance := range instances {
				if instance.State == "terminated" || instance.State == "shutting-down" {
					continue
				}
				terminateCtx, cancelTerminate := context.WithTimeout(ctx, 15*time.Second)
				err = provider.Terminate(terminateCtx, instance.ID)
				cancelTerminate()
				if err != nil {
					s.Store.DB.Exec(`UPDATE spot_launches SET next=?,error=?,updated=? WHERE id=?`, time.Now().Add(30*time.Second).Unix(), safeSpotError(err), time.Now().Unix(), launch.ID)
					terminated = true
					break
				}
				s.Store.DB.Exec(`UPDATE spot_launches SET state='terminating',instance_id=?,next=?,error='enrollment timeout',updated=? WHERE id=?`, instance.ID, time.Now().Add(30*time.Second).Unix(), time.Now().Unix(), launch.ID)
				invalidateSpotEnrollment(s.Store, launch.EnrollmentHash)
				terminated = true
				break
			}
			if !terminated {
				s.Store.DB.Exec(`UPDATE spot_launches SET state='failed',next=?,error='enrollment timeout',updated=? WHERE id=?`, time.Now().Add(15*time.Minute).Unix(), time.Now().Unix(), launch.ID)
				invalidateSpotEnrollment(s.Store, launch.EnrollmentHash)
			}
			continue
		}
		if len(instances) > 0 {
			foundActive := false
			seenTerminating := false
			for _, instance := range instances {
				if instance.State == "terminated" {
					if launch.State == "terminating" || launch.State == "enrolled" || launch.State == "running" && launch.MachineID != "" {
						s.Store.DB.Exec(`UPDATE spot_launches SET state='terminated',next=?,updated=? WHERE id=?`, time.Now().Unix(), time.Now().Unix(), launch.ID)
						markSpotMachineTerminated(s.Store, launch.MachineID)
					} else if launch.MachineID == "" {
						s.Store.DB.Exec(`UPDATE spot_launches SET state='terminated',next=?,error='instance terminated before enrollment',updated=? WHERE id=?`, time.Now().Unix(), time.Now().Unix(), launch.ID)
						invalidateSpotEnrollment(s.Store, launch.EnrollmentHash)
					}
					continue
				}
				if instance.State == "shutting-down" {
					seenTerminating = true
					s.Store.DB.Exec(`UPDATE spot_launches SET state='terminating',instance_id=?,next=?,updated=? WHERE id=?`, instance.ID, time.Now().Unix()+30, time.Now().Unix(), launch.ID)
					if launch.MachineID != "" {
						var machine capacity.Machine
						if s.Store.Read("machine", launch.MachineID, &machine) == nil {
							machine.State = "terminating"
							_ = s.Store.Put("machine", machine.ID, machine)
						}
					}
					continue
				}
				foundActive = true
				state := "running"
				if launch.MachineID != "" {
					state = launch.State
				}
				s.Store.DB.Exec(`UPDATE spot_launches SET state=?,instance_id=?,cpu=?,memory_mb=?,architecture=?,next=?,updated=?,error='' WHERE id=?`, state, instance.ID, instance.CPU, instance.MemoryMB, instance.Architecture, time.Now().Unix()+15, time.Now().Unix(), launch.ID)
			}
			if !foundActive {
				if seenTerminating || launch.State == "terminating" {
					s.Store.DB.Exec(`UPDATE spot_launches SET next=?,updated=? WHERE id=?`, time.Now().Unix()+30, time.Now().Unix(), launch.ID)
					continue
				}
				if launch.State == "enrolled" {
					s.Store.DB.Exec(`UPDATE spot_launches SET state='terminated',next=?,updated=? WHERE id=?`, time.Now().Unix(), time.Now().Unix(), launch.ID)
					markSpotMachineTerminated(s.Store, launch.MachineID)
					continue
				}
				fallbackAllowed := launch.Market == "spot" && spot.IsCapacityUnavailableCode(launch.Error) && spotConfig.FallbackAfterSeconds > 0 && len(spotConfig.OnDemandInstanceTypes) > 0 && time.Now().Unix()-launch.Created >= int64(spotConfig.FallbackAfterSeconds)
				if !fallbackAllowed {
					s.Store.DB.Exec(`UPDATE spot_launches SET state='failed',next=?,updated=?,error='instance terminated before enrollment' WHERE id=?`, time.Now().Add(15*time.Minute).Unix(), time.Now().Unix(), launch.ID)
					invalidateSpotEnrollment(s.Store, launch.EnrollmentHash)
					continue
				}
				s.Store.DB.Exec(`UPDATE spot_launches SET state='pending',updated=? WHERE id=?`, time.Now().Unix(), launch.ID)
			} else {
				continue
			}
		}
		if launch.State == "terminating" {
			s.Store.DB.Exec(`UPDATE spot_launches SET state='terminated',next=?,updated=? WHERE id=?`, time.Now().Unix(), time.Now().Unix(), launch.ID)
			markSpotMachineTerminated(s.Store, launch.MachineID)
			continue
		}
		if launch.State == "running" {
			if launch.InstanceID != "" {
				s.Store.DB.Exec(`UPDATE spot_launches SET state='running',next=?,updated=? WHERE id=?`, time.Now().Unix()+30, time.Now().Unix(), launch.ID)
			}
			continue
		}
		market := launch.Market
		typeName := launch.InstanceType
		if spot.IsCapacityUnavailableCode(launch.Error) {
			if launch.Market == "spot" && spotConfig.FallbackAfterSeconds > 0 && len(spotConfig.OnDemandInstanceTypes) > 0 && time.Now().Unix()-launch.Created >= int64(spotConfig.FallbackAfterSeconds) {
				market = "on-demand"
				typeName = spotConfig.OnDemandInstanceTypes[launch.Attempts%len(spotConfig.OnDemandInstanceTypes)]
			} else if launch.Market == "spot" && len(spotConfig.SpotInstanceTypes) > 0 {
				typeName = spotConfig.SpotInstanceTypes[launch.Attempts%len(spotConfig.SpotInstanceTypes)]
			} else if launch.Market == "on-demand" && len(spotConfig.OnDemandInstanceTypes) > 0 {
				typeName = spotConfig.OnDemandInstanceTypes[launch.Attempts%len(spotConfig.OnDemandInstanceTypes)]
			}
			launch.ClientToken = security.Random(32)
			s.Store.DB.Exec(`UPDATE spot_launches SET market=?,instance_type=?,client_token=?,state='pending',updated=? WHERE id=?`, market, typeName, launch.ClientToken, time.Now().Unix(), launch.ID)
		}
		code, err := s.enrollmentCode(launch.EnrollmentHash)
		if err != nil {
			s.Store.DB.Exec(`UPDATE spot_launches SET state='failed',error='enrollment credential unavailable',updated=? WHERE id=?`, time.Now().Unix(), launch.ID)
			invalidateSpotEnrollment(s.Store, launch.EnrollmentHash)
			continue
		}
		request := spot.LaunchRequest{
			LaunchID: launch.ID, PoolID: pool.ID, ClientToken: launch.ClientToken,
			BootstrapToken: code, MachineName: "rf-" + launch.ID[:12], ServerURL: s.Cfg.Origin,
			InstanceType: typeName, SubnetID: launch.SubnetID, Market: market, Config: *spotConfig,
			Architecture: launchPool.Arch,
			PoolCPU:      launchPool.CPU, PoolMemoryMB: launchPool.MemoryMB, PoolDiskMB: launchPool.DiskMB,
		}
		launchCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		instance, launchErr := provider.Launch(launchCtx, request)
		cancel()
		if launchErr != nil {
			attempts := launch.Attempts + 1
			next := time.Now().Add(time.Duration(min(attempts, 6)) * 15 * time.Second).Unix()
			s.Store.DB.Exec(`UPDATE spot_launches SET state='pending',attempts=?,next=?,error=?,updated=? WHERE id=?`, attempts, next, safeSpotError(launchErr), time.Now().Unix(), launch.ID)
			continue
		}
		s.Store.DB.Exec(`UPDATE spot_launches SET state='running',instance_id=?,cpu=?,memory_mb=?,architecture=?,attempts=attempts+1,next=?,updated=?,error='' WHERE id=?`, instance.ID, instance.CPU, instance.MemoryMB, instance.Architecture, time.Now().Unix()+15, time.Now().Unix(), launch.ID)
	}
	return nil
}

func invalidateSpotEnrollment(s *store.Store, hash string) {
	s.DB.Exec(`UPDATE enrollment SET used=1 WHERE hash=?`, hash)
	s.DB.Exec(`DELETE FROM kv WHERE key=?`, "spot-enrollment:"+hash)
}

func markSpotMachineTerminated(s *store.Store, machineID string) {
	if machineID == "" {
		return
	}
	var machine capacity.Machine
	if s.Read("machine", machineID, &machine) == nil {
		machine.State = "terminated"
		_ = s.Put("machine", machine.ID, machine)
	}
}

func (s *Server) enrollmentCode(hash string) (string, error) {
	var encrypted string
	if err := s.Store.DB.QueryRow(`SELECT value FROM kv WHERE key=?`, "spot-enrollment:"+hash).Scan(&encrypted); err != nil {
		return "", err
	}
	plain, err := security.Open(s.Key, encrypted)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func (s *Server) scaleInSpot(ctx context.Context, pool capacity.Pool, desired int) {
	if pool.Spot == nil {
		return
	}
	cloudMachines := []capacity.Machine{}
	for _, machine := range allMachines(s.Store) {
		if machine.ProviderPool == pool.ID && machine.CloudProvider == "aws" && machine.CloudInstanceID != "" && machine.State != "revoked" && machine.State != "terminated" && machine.State != "terminating" {
			cloudMachines = append(cloudMachines, machine)
		}
	}
	cloudSlots := 0
	for _, machine := range cloudMachines {
		cloudSlots += machinePoolSlots(machine, pool)
	}
	if cloudSlots <= desired {
		return
	}
	instances := allInstances(s.Store)
	for _, machine := range cloudMachines {
		machineSlots := machinePoolSlots(machine, pool)
		if cloudSlots-machineSlots < desired {
			continue
		}
		if time.Since(time.Unix(machine.IdleSince, 0)) < time.Duration(pool.Spot.IdleMinutes)*time.Minute || machine.IdleSince == 0 {
			continue
		}
		busy := false
		for _, instance := range instances {
			if instance.Machine == machine.ID && capacity.Active(instance.State) {
				if instance.State == "idle" && machine.State != "draining" {
					drainOnce(s.Store, machine.ID, instance.ID)
					machine.State = "draining"
					_ = s.Store.Put("machine", machine.ID, machine)
				}
				busy = true
				break
			}
		}
		if busy {
			continue
		}
		provider, err := s.spotProvider(ctx, machine.CloudRegion)
		if err != nil {
			continue
		}
		terminateCtx, cancelTerminate := context.WithTimeout(ctx, 15*time.Second)
		err = provider.Terminate(terminateCtx, machine.CloudInstanceID)
		cancelTerminate()
		if err != nil {
			s.alert("spot-terminate:"+machine.ID, "Falha ao terminar worker Spot", safeSpotError(err))
			continue
		}
		machine.State = "terminating"
		_ = s.Store.Put("machine", machine.ID, machine)
		s.Store.DB.Exec(`UPDATE spot_launches SET state='terminating',next=?,updated=? WHERE instance_id=?`, time.Now().Unix()+30, time.Now().Unix(), machine.CloudInstanceID)
		return
	}
}

func allMachines(s *store.Store) []capacity.Machine {
	rows, _ := s.List("machine")
	machines := []capacity.Machine{}
	for _, raw := range rows {
		var machine capacity.Machine
		if json.Unmarshal(raw, &machine) == nil {
			machines = append(machines, machine)
		}
	}
	return machines
}

func allInstances(s *store.Store) []capacity.Instance {
	instances, _ := capacity.List(s)
	return instances
}

func safeSpotError(err error) string {
	return spot.SafeErrorCode(err)
}

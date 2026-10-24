package discovery

import (
	"strings"
	"testing"
)

func TestAnalyzeMatricesReusableAndDynamic(t *testing.T) {
	src := `name: build
on: push
jobs:
  build:
    strategy:
      matrix:
        os: [ubuntu-24.04, ubuntu-22.04]
    runs-on: ${{ matrix.os }}
    steps: []
  custom:
    runs-on: [self-hosted, linux, x64]
  dynamic:
    runs-on: ${{ inputs.runner }}
  reuse:
    uses: ./other.yml
`
	jobs, e := Analyze(src)
	if e != nil {
		t.Fatal(e)
	}
	if len(jobs) != 4 || jobs[0].Status != "matrix" || len(jobs[0].Labels) != 2 || jobs[1].Status != "self-hosted" || jobs[2].Status != "unresolved" || jobs[3].Reusable == "" {
		t.Fatalf("%+v", jobs)
	}
}
func TestPatchPreservesUnrelatedContentAndRejectsComplex(t *testing.T) {
	src := "# keep\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest # note\n    steps:\n      - run: echo ok\n"
	got, e := Patch(src, "build", []string{"self-hosted", "linux"})
	if e != nil {
		t.Fatal(e)
	}
	want := strings.Replace(src, "ubuntu-latest", `["self-hosted", "linux"]`, 1)
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	src = "jobs:\n  a:\n    runs-on:\n      group: secure\n      labels: linux\n"
	if _, e = Patch(src, "a", []string{"self-hosted"}); e == nil {
		t.Fatal("complex destination rewritten")
	}
}

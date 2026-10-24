export type Row=Record<string,any>;
export let csrf='';
export function setCSRF(v:string){csrf=v;}
export async function api(path:string,method='GET',body?:unknown){const res=await fetch('/api'+path,{method,headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:body===undefined?undefined:JSON.stringify(body)});const data=await res.json();if(!res.ok)throw new Error(data.error||`HTTP ${res.status}`);return data;}
export const stamp=(n:number)=>n?new Date(n*1000).toLocaleString('pt-BR'):'—';

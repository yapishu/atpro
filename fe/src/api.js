const API='/apps/atpro/api';

async function request(url,body,method){
  const response=await fetch(url,{method:method||(body===undefined?'GET':'POST'),credentials:'same-origin',headers:body===undefined?{}:{'content-type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});
  const text=await response.text(); let data;
  try{data=text?JSON.parse(text):null}catch{data={error:text||`HTTP ${response.status}`}}
  if(!response.ok){const error=new Error(data?.message||data?.error||`HTTP ${response.status}`);error.status=response.status;throw error}
  return data;
}
export const api=(path,body)=>request(`${API}/${path}`,body);
export const admin=(agent,path,body)=>request(`/apps/atpro/${agent}/${path}`,body);
export const rpc=(target,method,nsid,query='',body)=>api('rpc',{target,method,nsid,query,...(body===undefined?{}:{body})});
export async function uploadBlob(file){
  const response=await fetch(`${API}/blob`,{method:'POST',credentials:'same-origin',headers:{'content-type':file.type||'application/octet-stream'},body:file});
  const data=await response.json(); if(!response.ok)throw new Error(data?.message||data?.error||`HTTP ${response.status}`); return data.blob;
}

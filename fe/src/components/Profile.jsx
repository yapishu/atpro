import React,{useEffect,useState} from 'react';
import {rpc} from '../api.js';
import Post from './Post.jsx';

export default function Profile({actor,initialMode='posts',account,onActor,onThread,onToggle,onGraph,onMode,onFollow}){
  const [profile,setProfile]=useState(null),[mode,setMode]=useState(initialMode),[feed,setFeed]=useState([]),[cursor,setCursor]=useState(''),[error,setError]=useState('');
  useEffect(()=>{rpc('pds','GET','app.bsky.actor.getProfile',`?actor=${encodeURIComponent(actor)}`).then(setProfile).catch(e=>setError(e.message))},[actor]);
  const load=async(nextMode=mode,nextCursor='',append=false)=>{setMode(nextMode);setError('');try{const q=`?actor=${encodeURIComponent(actor)}&limit=50${nextCursor?`&cursor=${encodeURIComponent(nextCursor)}`:''}`;const data=nextMode==='likes'?await rpc('pds','GET','app.bsky.feed.getActorLikes',q):await rpc('pds','GET','app.bsky.feed.getAuthorFeed',`${q}&filter=${nextMode==='posts'?'posts_no_replies':'posts_with_replies'}`);const items=nextMode==='replies'?(data.feed||[]).filter(x=>x.post?.record?.reply):(data.feed||[]);setFeed(old=>append?[...old,...items]:items);setCursor(data.cursor||'')}catch(e){setError(e.message)}};
  useEffect(()=>{load(initialMode)},[actor,initialMode]);
  if(error&&!profile)return <div className="empty">{error}</div>; if(!profile)return <div className="empty"><span className="spinner"/></div>;
  const own=profile.did===account.did;
  return <><section className="profile-head">{profile.avatar?<img className="avatar" src={profile.avatar}/>:<div className="avatar"/>}<div><div className="name">{profile.displayName||profile.handle}</div><div className="handle">@{profile.handle}</div><div className="profile-stats"><button className="stat-link" onClick={()=>onGraph(profile.did,'followers')}>{profile.followersCount||0} followers</button><button className="stat-link" onClick={()=>onGraph(profile.did,'following')}>{profile.followsCount||0} following</button><span>{profile.postsCount||0} posts</span></div><div className="bio">{profile.description}</div>{!own&&<button className={`ghost ${profile.viewer?.following?'on':''}`} onClick={async()=>setProfile(await onFollow(profile))}>{profile.viewer?.following?'unfollow':'follow'}</button>}</div></section>
  <div className="profile-tabs">{['posts','replies',...(own?['likes']:[])].map(x=><button key={x} className={mode===x?'active':''} onClick={()=>onMode(x)}>{x}</button>)}</div>
  {error&&<div className="empty">{error}</div>}{feed.length?feed.map((x,i)=><Post key={x.post?.uri||i} item={x} context={mode==='replies'?(x.reply?.parent?.author?.handle?`reply to @${x.reply.parent.author.handle}`:'reply'):''} onActor={onActor} onThread={onThread} onToggle={onToggle}/>):!error&&<div className="empty">No {mode} found.</div>}
  {cursor&&<div className="form-body"><button className="ghost" onClick={()=>load(mode,cursor,true)}>load more</button></div>}</>;
}

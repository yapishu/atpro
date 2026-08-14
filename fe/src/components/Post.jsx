import React from 'react';

const safe=url=>{try{const u=new URL(url);return /^https?:$/.test(u.protocol)?u.href:''}catch{return''}};
export const ago=value=>{const s=Math.max(1,(Date.now()-new Date(value).getTime())/1000);return s<60?`${Math.floor(s)}s`:s<3600?`${Math.floor(s/60)}m`:s<86400?`${Math.floor(s/3600)}h`:new Date(value).toLocaleDateString()};

export default function Post({item,context,onActor,onThread,onToggle}){
  const post=item.post||item, author=post.author||{}, record=post.record||{};
  const images=(post.embed?.images||post.embed?.media?.images||[]).filter(x=>safe(x.thumb));
  return <article className="post" onClick={()=>onThread(post.uri)}>
    <button className="avatar-button" onClick={e=>{e.stopPropagation();onActor(author.did||author.handle)}}>{author.avatar?<img className="avatar" src={author.avatar}/>:<span className="avatar"/>}</button>
    <div>{context&&<div className="reply-context">{context}</div>}<div className="who"><button className="author-link name" onClick={e=>{e.stopPropagation();onActor(author.did||author.handle)}}>{author.displayName||author.handle||'Unknown'}</button><span className="handle">@{author.handle}</span><span className="time">· {ago(record.createdAt)}</span></div><div className="body">{record.text}</div>
    {!!images.length&&<div className="post-media" data-count={images.length}>{images.map((x,i)=><a className="media-frame" key={i} href={safe(x.fullsize)||safe(x.thumb)} target="_blank" onClick={e=>e.stopPropagation()}><img src={safe(x.thumb)} alt={x.alt||''}/></a>)}</div>}
    <div className="post-stats"><button className={`stat-link ${post.viewer?.like?'on':''}`} onClick={e=>{e.stopPropagation();onToggle('like',post)}}>♡ {post.likeCount||0}</button><button className={`stat-link ${post.viewer?.repost?'on':''}`} onClick={e=>{e.stopPropagation();onToggle('repost',post)}}>↻ {post.repostCount||0}</button><button className="stat-link">◌ {post.replyCount||0} replies</button></div></div>
  </article>;
}

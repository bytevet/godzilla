import React from 'react';
import DOMPurify from 'dompurify';

// dangerouslySetInnerHTML is React's one documented way out of JSX's
// auto-escaping, so a browser-controlled value reaching it is XSS.
export function Bio() {
  const bio = window.location.hash;
  return <div className="bio" dangerouslySetInnerHTML={{__html: bio}} />;
}

// The object may be built apart from the attribute; the taint is the same.
export function IndirectBio() {
  const html = {__html: document.URL};
  return <div dangerouslySetInnerHTML={html} />;
}

// Three shapes that must NOT fire: ordinary JSX children escape, a sanitized
// value is neutralized, and a constant was never tainted.
export function Safe() {
  const bio = window.location.hash;
  return (
    <div>
      <span>{bio}</span>
      <div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(bio)}} />
      <div dangerouslySetInnerHTML={{__html: '<b>static</b>'}} />
    </div>
  );
}

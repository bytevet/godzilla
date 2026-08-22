import React from 'react';
import DOMPurify from 'dompurify';

// ghost CVE-2026-24778: a site setting reaches the component as React CONTEXT
// and is rendered raw. Destructured off a field chain on purpose -- only the
// first hop off `this` becomes a matchable callee, so this pins that the
// remaining field reads still carry the base's taint.
export class SignupPage extends React.Component {
  render() {
    const { portal_signup_terms_html } = this.context.site;
    return <div dangerouslySetInnerHTML={{__html: portal_signup_terms_html}} />;
  }
}

// A class component's props, read directly at the sink.
export class Bio extends React.Component {
  render() {
    return <div dangerouslySetInnerHTML={{__html: this.props.bio}} />;
  }
}

// The dominant React idiom: props destructured in the signature. The pattern
// binds no identifier of its own, so without the frontend binding each property
// the prop is not a value this rule can see at all.
export function Note({html}) {
  return <div dangerouslySetInnerHTML={{__html: html}} />;
}

// A named props parameter, the other function-component spelling.
export function Card(props) {
  return <div dangerouslySetInnerHTML={{__html: props.body}} />;
}

// Two shapes that must NOT fire: a sanitized prop, and escaped JSX children.
export function SafeNote({html}) {
  return (
    <div>
      <span>{html}</span>
      <div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(html)}} />
    </div>
  );
}

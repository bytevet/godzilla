import React from 'react';

// A lowercase-named helper is not a component -- JSX compiles a lowercase tag to
// a host-element string, so this can never be rendered as one and its options bag
// is not props. This is the sample that pins the capital-initial predicate: a
// broader one ("first parameter is a destructured object") passes CI without it.
export function buildMarkup({html}) {
  return <div dangerouslySetInnerHTML={{__html: html}} />;
}

// A component whose props reach only escaped children.
export function Bio({bio}) {
  return <span>{bio}</span>;
}

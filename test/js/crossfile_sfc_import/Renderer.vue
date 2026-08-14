<script>
// Default-exported sink wrapper living in an SFC, imported by app.js below.
const _conn = require("some-db");

export default function render(q) {
  return _conn.query(q); // SQL sink, a cross-file hop from the handler
}
</script>

<template>
  <div>rendered</div>
</template>

<!-- Vue SFC with a reflected XSS via v-html.
     A component prop (external input from a parent, often derived from the URL)
     is bound to v-html, which renders it as raw HTML and bypasses Vue's
     context-aware auto-escaping — an attacker-controlled `bio` injects markup. -->
<script setup>
const props = defineProps(['bio'])
const bio = props.bio
</script>

<template>
  <section class="profile">
    <h1>Profile</h1>
    <div v-html="bio"></div>
  </section>
</template>

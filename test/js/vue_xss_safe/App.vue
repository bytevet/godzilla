<!-- Safe Vue SFC (FP guard). Two true-negatives:
     1. `{{ props.bio }}` text interpolation is auto-escaped — no sink emitted.
     2. `v-html="clean"` binds a DOMPurify-sanitized value, so the sink argument
        is not tainted and must not fire. -->
<script setup>
import DOMPurify from 'dompurify'
const props = defineProps(['bio'])
const clean = DOMPurify.sanitize(props.bio)
</script>

<template>
  <section class="profile">
    <p>{{ props.bio }}</p>
    <div v-html="clean"></div>
  </section>
</template>

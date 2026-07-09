<!-- Safe Svelte component (FP guard). Ordinary `{bio}` interpolation is
     auto-escaped by Svelte — no {@html}, so no sink is emitted. -->
<script>
  let bio = window.location.search;
</script>

<section class="profile">
  <h1>Profile</h1>
  <div>{bio}</div>
</section>

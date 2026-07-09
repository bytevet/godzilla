<!-- Svelte component with a reflected XSS via {@html}.
     The browser-controlled query string flows into {@html}, which renders raw
     HTML and bypasses Svelte's default text-escaping. -->
<script>
  let bio = window.location.search;
</script>

<section class="profile">
  <h1>Profile</h1>
  <div>{@html bio}</div>
</section>

async function load(name) { const m = await import("./" + name); return m; }
module.exports = { load };

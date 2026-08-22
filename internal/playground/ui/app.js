/* gIR Playground — interaction.

   The client for internal/playground: the server lowers the target once and
   this renders it. Two behaviours matter more than anything else here.

   1. Logical argument numbering. A statically-resolved method call passes its
      RECEIVER as args[0] and sets method_name, so the index a rule pins with
      #<n> is the physical index minus one. An interface invoke keeps its
      receiver in call.value, so there the two coincide. Getting this wrong is
      the silent failure the tool exists to prevent, so the receiver is drawn as
      `recv` and never given a number.

   2. Pattern matching and sink/source classification are NOT done here. Both
      run server-side on internal/rules, so what this draws is the engine's own
      verdict rather than a second implementation of it that could drift. */
(function () {
  "use strict";
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };
  var DENSITY = document.documentElement.getAttribute("data-density") || "open";
  var ROW_H = 20, VIRT_OVER = 1200, SRC_CAP = 5000, MATCH_DEBOUNCE = 80;

  /* ── server ────────────────────────────────────────────────────────── */
  function api(path, body) {
    var opt = body === undefined ? undefined
      : { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) };
    return fetch(path, opt).then(function (r) {
      if (!r.ok) throw new Error(r.status + " " + r.statusText);
      return r.json();
    });
  }
  function fail(msg) {
    $("#code").innerHTML = '<div class="statebox">' + stateIcon("warn") +
      "<h3>Lost the server</h3><p>" + esc(String(msg)) + "</p></div>";
  }

  /* ── theme ─────────────────────────────────────────────────────────── */
  var root = document.documentElement, TKEY = "gir-theme", tgl = $("#theme-toggle");
  var darkMQ = matchMedia("(prefers-color-scheme: dark)");
  function eff() { return root.getAttribute("data-theme") || (darkMQ.matches ? "dark" : "light"); }
  function paintTgl() { if (tgl) tgl.setAttribute("data-eff", eff()); }
  try { var sv = localStorage.getItem(TKEY); if (sv === "dark" || sv === "light") root.setAttribute("data-theme", sv); } catch (e) {}
  paintTgl();
  if (tgl) tgl.addEventListener("click", function () {
    var n = eff() === "dark" ? "light" : "dark";
    root.setAttribute("data-theme", n);
    try { localStorage.setItem(TKEY, n); } catch (e) {}
    paintTgl();
  });
  darkMQ.addEventListener("change", paintTgl);

  /* ── helpers ───────────────────────────────────────────────────────── */
  /* Quotes are escaped as well as angle brackets: several call sites below
     interpolate into an attribute, and the strings here are literals lifted out
     of SCANNED source. A SAST tool's own UI must not be XSS-able by the code it
     was pointed at. */
  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }
  var OPS = {
    OP_CODE_RET: "ret", OP_CODE_JUMP: "jump", OP_CODE_IF: "if", OP_CODE_SWITCH: "switch",
    OP_CODE_PANIC: "panic", OP_CODE_UNREACHABLE: "unreachable", OP_CODE_ALLOC: "alloc",
    OP_CODE_LOAD: "load", OP_CODE_STORE: "store", OP_CODE_FIELD: "field",
    OP_CODE_FIELD_ADDR: "field.addr", OP_CODE_INDEX: "index", OP_CODE_INDEX_ADDR: "index.addr",
    OP_CODE_BIN_OP: "binop", OP_CODE_UN_OP: "unop", OP_CODE_PHI: "phi", OP_CODE_CALL: "call",
    OP_CODE_INVOKE: "invoke", OP_CODE_CONVERT: "convert", OP_CODE_TYPE_ASSERT: "typeassert",
    OP_CODE_MAKE_INTERFACE: "makeiface", OP_CODE_EXTRACT: "extract", OP_CODE_INTRINSIC: "intrinsic"
  };
  var BINOPS = {
    BIN_OP_ADD: "+", BIN_OP_SUB: "-", BIN_OP_MUL: "*", BIN_OP_QUO: "/", BIN_OP_REM: "%",
    BIN_OP_AND: "&", BIN_OP_OR: "|", BIN_OP_XOR: "^", BIN_OP_SHL: "<<", BIN_OP_SHR: ">>"
  };
  var UNOPS = { UN_OP_NOT: "!", UN_OP_BIT_NOT: "^", UN_OP_NEG: "-", UN_OP_POS: "+",
                UN_OP_ADDR: "&", UN_OP_DEREF: "*", UN_OP_ARROW: "<-" };

  function valText(v) {
    if (!v) return "?";
    if (v.reg_name) return v.reg_name;
    if (v.global_name) return "@" + v.global_name;
    if (v.func_name) return v.func_name;
    var c = v.constant;
    if (!c) return "?";
    return c.type === "string" ? '"' + c.string_val + '"' : String(c.string_val);
  }
  function valHTML(v) {
    if (!v) return "?";
    if (v.reg_name) return '<span class="reg">' + esc(v.reg_name) + "</span>";
    if (v.global_name) return '<span class="callee">@' + esc(v.global_name) + "</span>";
    if (v.func_name) return '<span class="callee">' + esc(v.func_name) + "</span>";
    return '<span class="lit">' + esc(valText(v)) + "</span>";
  }
  function shortStr(s, n) { n = n || 30; return s.length > n ? s.slice(0, n - 1) + "\u2026" : s; }

  /* receiver shift: a static method call carries its receiver as args[0] */
  function recvShift(call) { return call && call.method_name && !call.is_invoke ? 1 : 0; }

  /* The server already asked the loaded rules (language gate included) and
     stamped the verdict onto the instruction, so this is a field read. */
  function classify(ins) { return (ins && ins.flag) || null; }

  /* ── source highlighting ───────────────────────────────────────────── */
  var FAMILY = {
    c: { line: "\\/\\/", block: true,
      kw: /^(func|var|const|if|else|for|range|return|package|import|type|struct|interface|map|chan|go|defer|select|switch|case|default|break|continue|nil|true|false|class|public|private|protected|static|final|void|new|extends|implements|throws|try|catch|finally|this|super|enum|let|function|async|await|export|as|in|string|int|bool|float|uint|byte|any|error)$/ },
    hash: { line: "#", block: false,
      kw: /^(def|class|if|elif|else|for|while|return|import|from|as|try|except|finally|with|lambda|None|True|False|and|or|not|in|is|pass|raise|yield|global|assert|del|self)$/ }
  };
  var LANGFAM = { go: "c", java: "c", javascript: "c", typescript: "c", c: "c", cpp: "c",
                  rust: "c", kotlin: "c", swift: "c", php: "c", python: "hash", ruby: "hash",
                  shell: "hash", yaml: "hash" };
  var lexCache = {};
  function lexer(lang) {
    var name = LANGFAM[lang] || "c";
    if (!lexCache[name]) {
      var f = FAMILY[name];
      lexCache[name] = {
        kw: f.kw,
        re: new RegExp("(" + f.line + ".*" + (f.block ? "|\\/\\*[\\s\\S]*?\\*\\/" : "") + ")" +
          "|(\"(?:\\\\.|[^\"\\\\])*\"|`[^`]*`|'(?:\\\\.|[^'\\\\])*')" +
          "|(\\d[\\w.]*)|([A-Za-z_]\\w*)|(\\s+)|([^\\s\\w]+)", "g")
      };
    }
    return lexCache[name];
  }
  function highlight(src, lang) {
    var L = lexer(lang), out = "", m;
    L.re.lastIndex = 0;
    while ((m = L.re.exec(src))) {
      var t = m[0];
      if (m[1]) out += '<span class="t-com">' + esc(t) + "</span>";
      else if (m[2]) out += '<span class="t-str">' + esc(t) + "</span>";
      else if (m[3]) out += '<span class="t-num">' + esc(t) + "</span>";
      else if (m[4]) {
        if (L.kw.test(t)) out += '<span class="t-kw">' + t + "</span>";
        else if (src.charAt(L.re.lastIndex) === "(") out += '<span class="t-fn">' + t + "</span>";
        else out += esc(t);
      } else if (m[6]) out += '<span class="t-op">' + esc(t) + "</span>";
      else out += esc(t);
    }
    return out;
  }

  /* ── empty states ──────────────────────────────────────────────────── */
  var EMPTY = {
    "empty-nofile": { icon: "file", t: "No file selected", d: "Pick a file on the left to lower it to gIR." },
    "empty-nofunc": { icon: "file", t: "No functions in this module",
      d: "The file parsed cleanly, but it declares no functions \u2014 there is nothing to lower." },
    "empty-failed": { icon: "warn", t: "Converter produced no gIR for this file",
      d: "The file is skipped, so its sinks are invisible to every rule." }
  };

  var files = [], file = null, presets = null;

  /* ── model ─────────────────────────────────────────────────────────── */
  var nodes = [], byLine = {}, byOrd = {}, open = {}, visible = [];
  var selNode = null, fanout = [], fanIdx = 0, pattern = "", virt = false;
  var matched = null; // ords the server reported for the current pattern

  function argsHTML(call) {
    var shift = recvShift(call), out = "";
    (call.args || []).forEach(function (a, i) {
      if (i) out += '<span class="nmeta">, </span>';
      var disp = a.constant && a.constant.type === "string"
        ? '<span class="lit">"' + esc(shortStr(a.constant.string_val)) + '"</span>' : valHTML(a);
      if (i < shift) {
        out += '<span class="arg recv" data-arg="recv" title="receiver \u2014 excluded from logical numbering">' +
          disp + '<span class="ix">recv</span></span>';
      } else {
        var lg = i - shift;
        out += '<span class="arg" data-arg="' + lg + '" title="logical arg #' + lg +
          " (physical " + i + ")" + (a.name ? " \u00b7 keyword " + a.name : "") +
          ' \u2014 click for a pattern">' + disp + '<span class="ix">#' + lg + "</span></span>";
      }
    });
    return out;
  }

  function instrHTML(ins) {
    var out = "";
    if (ins.name) out += '<span class="reg">' + esc(ins.name) + '</span> <span class="nmeta">=</span> ';
    var op = OPS[ins.op] || ins.op;
    if (ins.call) {
      var c = ins.call, callee = "";
      out += '<span class="op">' + esc(op) + "</span> ";
      if (c.is_invoke) {
        out += '<span class="arg recv" data-arg="recv" title="invoke receiver \u2014 in call.value, not in args">' +
          valHTML(c.value) + '<span class="ix">recv</span></span><span class="nmeta">.</span>' +
          '<span class="callee">' + esc(c.method_name || "") + "</span>";
      } else {
        callee = c.callee || valText(c.value);
        out += '<span class="callee">' + esc(callee) + "</span>";
      }
      out += '<span class="nmeta">(</span>' + argsHTML(c) + '<span class="nmeta">)</span>';
      /* The tag names the intrinsic a NON-intrinsic call carries (fmt.Sprintf as
         builtin.format). A call-shaped intrinsic already reads as its own name. */
      if (ins.intrinsic && ins.intrinsic !== callee) out += ' <span class="intr">' + esc(ins.intrinsic) + "</span>";
      if (c.untyped_dispatch) out += ' <span class="nmeta">untyped</span>';
      return out;
    }
    if (ins.op === "OP_CODE_BIN_OP") {
      return out + valHTML(ins.operands[0]) + ' <span class="op">' +
        esc(BINOPS[ins.bin_op] || ins.bin_op) + "</span> " + valHTML(ins.operands[1]);
    }
    if (ins.op === "OP_CODE_UN_OP") {
      return out + '<span class="op">' + esc(UNOPS[ins.un_op] || ins.un_op) + "</span>" +
        valHTML(ins.operands[0]);
    }
    if (ins.op === "OP_CODE_INTRINSIC") {
      out += '<span class="op">intrinsic</span> <span class="intr">' + esc(ins.intrinsic) + "</span>";
      if (ins.operands && ins.operands.length)
        out += '<span class="nmeta">(</span>' + ins.operands.map(valHTML).join('<span class="nmeta">, </span>') +
          '<span class="nmeta">)</span>';
      return out;
    }
    if (ins.op === "OP_CODE_IF") {
      return out + '<span class="op">if</span> ' + valHTML(ins.operands[0]) +
        ' <span class="nmeta">goto</span> <span class="callee blk" data-goblock="' + esc(ins.true_block) +
        '">' + esc(ins.true_block) + '</span> <span class="nmeta">else</span> ' +
        '<span class="callee blk" data-goblock="' + esc(ins.false_block) + '">' + esc(ins.false_block) + "</span>";
    }
    if (ins.op === "OP_CODE_JUMP") {
      return out + '<span class="op">jump</span> <span class="callee blk" data-goblock="' +
        esc(ins.jump_block) + '">' + esc(ins.jump_block) + "</span>";
    }
    out += '<span class="op">' + esc(op) + "</span>";
    if (ins.op === "OP_CODE_FIELD" || ins.op === "OP_CODE_EXTRACT") {
      out += " " + (ins.operands || []).map(valHTML).join('<span class="nmeta">, </span>') +
        ' <span class="nmeta">[' + ins.field_index + "]</span>";
    } else if (ins.operands && ins.operands.length) {
      out += " " + ins.operands.map(valHTML).join('<span class="nmeta">, </span>');
    } else if (ins.type) {
      out += ' <span class="nmeta">' + esc(ins.type) + "</span>";
    }
    if (ins.heap) out += ' <span class="nmeta">heap</span>';
    return out;
  }

  function add(rec) {
    rec.kids = [];
    nodes.push(rec);
    var i = nodes.length - 1;
    if (rec.parent != null) nodes[rec.parent].kids.push(i);
    if (rec.line) (byLine[rec.line] = byLine[rec.line] || []).push(i);
    return i;
  }

  function build() {
    nodes = []; byLine = {}; byOrd = {}; open = {};
    if (!file) return;
    var m = file.module;
    var mid = add({ kind: "module", label: m.name, line: null, data: m, depth: 0, parent: null,
      html: '<span class="nname">' + esc(m.name) + '</span> <span class="nmeta">\u00b7 ' + esc(m.language) +
        " \u00b7 " + m.functions.length + " func \u00b7 " + m.globals.length + " global \u00b7 " +
        m.types.length + " type</span>" });
    open[mid] = true;

    m.globals.forEach(function (g) {
      add({ kind: "global", label: g.name, line: g.pos && g.pos.line, data: g, depth: 1, parent: mid,
        cls: g.pos ? "" : "nopos", kind_cls: "type", kind_txt: "global",
        html: '<span class="nname">@' + esc(g.name) + '</span> <span class="nmeta">' + esc(g.type) +
          "</span>" + (g.synthetic ? ' <span class="nopos-tag">synthetic</span>' : "") });
    });
    m.types.forEach(function (t) {
      var tid = add({ kind: "type", label: t.name, line: t.pos && t.pos.line, data: t, depth: 1,
        parent: mid, kind_cls: "type", kind_txt: "type",
        html: '<span class="nname">' + esc(t.name) + '</span> <span class="nmeta">' +
          esc(String(t.underlying).replace("TYPE_KIND_", "").toLowerCase()) + " \u00b7 " +
          t.fields.length + " field</span>" });
      t.fields.forEach(function (fl) {
        add({ kind: "field", label: fl.name, line: null, data: fl, depth: 2, parent: tid, cls: "nopos",
          html: '<span class="nname">' + esc(fl.name) + '</span> <span class="nmeta">' + esc(fl.type) +
            "</span>" + (fl.tag ? ' <span class="lit">' + esc(fl.tag) + "</span>" : "") });
      });
    });
    m.functions.forEach(function (f, fi) {
      var nInstr = f.blocks.reduce(function (a, b) { return a + b.instrs.length; }, 0);
      var fid = add({ kind: "func", label: f.object_name, line: f.pos && f.pos.line, data: f,
        depth: 1, parent: mid, kind_cls: "func", kind_txt: "func", cls: f.pos ? "" : "nopos",
        html: '<span class="nname">' + esc(f.object_name) + '</span> <span class="nmeta">' +
          esc(f.canonical_name) + " \u00b7 " + f.blocks.length + "b/" + nInstr + "i</span>" +
          (f.synthetic ? ' <span class="nopos-tag">synthetic</span>' : "") });
      if (DENSITY === "open" && fi <= 1) open[fid] = true;

      f.blocks.forEach(function (b) {
        function chip(n) { return '<span class="callee blk" data-goblock="b' + n + '">b' + n + "</span>"; }
        var chips = "";
        if (b.preds.length) chips += ' <span class="nmeta">preds</span> ' + b.preds.map(chip).join(" ");
        if (b.succs.length) chips += ' <span class="nmeta">succs</span> ' + b.succs.map(chip).join(" ");
        var bid = add({ kind: "block", label: "b" + b.index, line: null, data: b, fn: f, depth: 2,
          parent: fid, kind_cls: "block", kind_txt: "b" + b.index,
          html: '<span class="nname">' + esc(b.comment) + "</span>" + chips +
            ' <span class="nmeta">\u00b7 ' + b.instrs.length + "i</span>" });
        if (DENSITY === "open") open[bid] = true;

        b.instrs.forEach(function (ins) {
          var cls = classify(ins), flags = "";
          if (cls && cls.kind === "sink")
            flags += ' <span class="sinkflag" title="' + esc(cls.rule + (cls.cwe ? " \u00b7 " + cls.cwe : "")) +
              '">sink' + (cls.idx != null ? " #" + cls.idx : " (all args)") + "</span>";
          if (cls && cls.kind === "source")
            flags += ' <span class="sinkflag srcflag" title="' + esc(cls.rule) + '">source</span>';
          if (!ins.pos) flags += ' <span class="nopos-tag">no source position</span>';
          var ni = add({ kind: "instr", label: ins.name || OPS[ins.op] || ins.op,
            line: ins.pos && ins.pos.line, col: ins.pos && ins.pos.column,
            data: ins, fn: f, block: b, depth: 3, parent: bid,
            cls: ins.pos ? "" : "nopos", html: instrHTML(ins) + flags });
          if (ins.ord != null) byOrd[ins.ord] = ni;
        });
      });
    });
  }

  function computeVisible() {
    visible = [];
    (function walk(i) {
      visible.push(i);
      if (!open[i]) return;
      nodes[i].kids.forEach(walk);
    })(0);
    virt = visible.length > VIRT_OVER;
  }
  function rowHTML(i) {
    var n = nodes[i];
    return '<button class="nrow' + (n.cls ? " " + n.cls : "") +
      (i === selNode ? " sel" : (fanout.indexOf(i) !== -1 ? " hit" : "")) +
      (n.match ? " match" : "") + '" type="button" data-node="' + i +
      '" style="padding-left:' + (8 + n.depth * 14) + 'px">' +
      '<span class="tw' + (n.kids.length ? (open[i] ? " on" : "") : " leaf") + '"></span>' +
      (n.kind_txt ? '<span class="kind ' + (n.kind_cls || "") + '">' + n.kind_txt + "</span>" : "") +
      n.html + "</button>";
  }
  function renderIR() {
    if (!nodes.length) return;
    computeVisible();
    var box = $("#ir-wrap"), host = $("#ir");
    if (!virt) {
      host.style.height = "";
      host.innerHTML = '<div class="rows" style="transform:none">' + visible.map(rowHTML).join("") + "</div>";
    } else {
      var first = Math.max(0, Math.floor(box.scrollTop / ROW_H) - 20);
      var count = Math.ceil(box.clientHeight / ROW_H) + 40;
      host.style.height = visible.length * ROW_H + "px";
      host.innerHTML = '<div class="rows" style="transform:translateY(' + (first * ROW_H) + 'px)">' +
        visible.slice(first, first + count).map(rowHTML).join("") + "</div>";
    }
    $("#ir-count").textContent = visible.length.toLocaleString() + " rows \u00b7 " +
      nodes.length.toLocaleString() + " nodes" + (virt ? " \u00b7 windowed" : "");
    var note = $("#virt-note");
    note.hidden = nodes.length < 4000;
    note.textContent = virt ? "windowed \u00b7 " + visible.length.toLocaleString() + " rows"
                            : "large module \u00b7 " + nodes.length.toLocaleString() + " nodes";
  }

  /* ── source column ─────────────────────────────────────────────────── */
  function renderCode() {
    if (!file) { $("#code").innerHTML = ""; return; }
    var out = [], src = file.src, cap = Math.min(src.length, SRC_CAP);
    for (var i = 0; i < Math.min(src.length, cap); i++) {
      var n = i + 1, hits = (byLine[n] || []).length;
      out.push('<button class="cline ' + (hits ? "has" : "nomap") + '" type="button" data-line="' + n + '"' +
        (hits ? "" : ' tabindex="-1"') + '><span class="ln">' + n + '</span><span class="tx">' +
        (src[i] ? highlight(src[i], file.lang) : " ") + "</span>" +
        (hits ? '<span class="dots" title="' + hits + ' gIR node' + (hits > 1 ? "s" : "") + '">' +
          new Array(Math.min(hits, 4) + 1).join("<i></i>") + "</span>" : "") + "</button>");
    }
    if (src.length > cap)
      out.push('<div class="more">' + (src.length - cap).toLocaleString() +
        " more lines not drawn \u2014 only the gIR column is windowed</div>");
    $("#code").innerHTML = out.join("");
  }

  /* ── selection ─────────────────────────────────────────────────────── */
  function scrollBox(box, el) {
    if (!box || !el) return;
    var t = el.getBoundingClientRect().top - box.getBoundingClientRect().top;
    if (t < 24 || t > box.clientHeight - 32) box.scrollTop += t - box.clientHeight / 3;
  }
  function revealNode(i) {
    var p = nodes[i].parent;
    while (p != null) { open[p] = true; p = nodes[p].parent; }
    renderIR();
    var box = $("#ir-wrap");
    if (virt) {
      var pos = visible.indexOf(i);
      if (pos >= 0) {
        var want = pos * ROW_H - box.clientHeight / 3;
        if (Math.abs(box.scrollTop - want) > box.clientHeight / 2) {
          box.scrollTop = Math.max(0, want);
          renderIR();
        }
      }
    } else scrollBox(box, $('#ir .nrow[data-node="' + i + '"]'));
  }
  function pickLine(line) {
    fanout = (byLine[line] || []).slice();
    fanIdx = 0;
    selNode = fanout.length ? fanout[0] : null;
    paint();
    if (selNode != null) revealNode(selNode);
  }
  function pickNode(i) {
    selNode = i;
    var line = nodes[i].line;
    fanout = line ? (byLine[line] || []).slice() : [i];
    fanIdx = Math.max(0, fanout.indexOf(i));
    paint();
  }
  function step(d) {
    if (fanout.length < 2) return;
    fanIdx = (fanIdx + d + fanout.length) % fanout.length;
    selNode = fanout[fanIdx];
    paint();
    revealNode(selNode);
  }
  function paint() {
    var rec = selNode != null ? nodes[selNode] : null, line = rec ? rec.line : null;
    $$("#code .cline").forEach(function (el) {
      el.classList.toggle("sel", !!line && +el.getAttribute("data-line") === line);
    });
    document.body.classList.toggle("has-sel", selNode != null);
    var st = $("#stepper");
    if (fanout.length > 1) {
      st.hidden = false;
      $("#step-lbl").textContent = (fanIdx + 1) + " of " + fanout.length + " nodes on line " + line;
    } else st.hidden = true;
    markMatches();
    renderIR();
    renderInspector(rec);
    if (line) scrollBox($("#code-wrap"), $('#code .cline[data-line="' + line + '"]'));
  }

  /* ── inspector ─────────────────────────────────────────────────────── */
  function renderInspector(rec) {
    var box = $("#insp-body"), sum = $("#insp-sum");
    if (!rec) {
      sum.textContent = "no selection";
      box.innerHTML = '<div class="empty">Click a source line or a gIR node \u2014 both sides stay in step.</div>';
      return;
    }
    var d = rec.data, rows = [];
    function row(k, v) { rows.push([k, v == null || v === "" ? '<span class="null">\u2014</span>' : v]); }

    if (rec.kind === "instr") {
      row("name", d.name ? '<span class="reg">' + esc(d.name) + "</span>" : null);
      row("op", esc(d.op));
      row("type", esc(d.type));
      row("pos", d.pos ? esc(file.path + ":" + d.pos.line + ":" + d.pos.column)
                       : '<span class="null">none \u2014 no source position</span>');
      if (d.comment) row("comment", esc(d.comment));
      if (d.intrinsic) row("intrinsic", '<span class="intr">' + esc(d.intrinsic) + "</span>");
      if (d.bin_op && d.op === "OP_CODE_BIN_OP") row("bin_op", esc(d.bin_op));
      if (d.un_op && d.op === "OP_CODE_UN_OP") row("un_op", esc(d.un_op));
      if (d.op === "OP_CODE_FIELD" || d.op === "OP_CODE_EXTRACT" || d.op === "OP_CODE_FIELD_ADDR")
        row("field_index", String(d.field_index));
      if (d.heap) row("heap", "true");
      if (d.operands && d.operands.length)
        row("operands", d.operands.map(valHTML).join('<span class="nmeta">, </span>'));
      if (d.true_block) row("true_block", esc(d.true_block));
      if (d.false_block) row("false_block", esc(d.false_block));
      if (d.jump_block) row("jump_block", esc(d.jump_block));
      if (d.call) {
        row("call.callee", d.call.callee ? '<span class="callee">' + esc(d.call.callee) + "</span>" : null);
        row("call.is_invoke", String(!!d.call.is_invoke));
        if (d.call.method_name) row("call.method_name", esc(d.call.method_name));
        if (d.call.untyped_dispatch) row("call.untyped_dispatch", "true");
        var shift = recvShift(d.call);
        (d.call.args || []).forEach(function (a, i) {
          var lbl = i < shift ? "args[" + i + "] recv" : "args[" + i + "] &rarr; #" + (i - shift);
          row(lbl, valHTML(a) + (a.name ? ' <span class="nmeta">kw ' + esc(a.name) + "</span>" : ""));
        });
        if (shift) rows.push(["", '<span class="nmeta">receiver excluded from logical numbering, ' +
          'so a rule pins #0 for args[1]</span>']);
      }
      row("function", '<span class="nmeta">' + esc(rec.fn.canonical_name) + "</span>");
      row("block", "b" + rec.block.index + " \u00b7 " + esc(rec.block.comment));
    } else if (rec.kind === "func") {
      row("name", esc(d.name));
      row("canonical_name", '<span class="callee">' + esc(d.canonical_name) + "</span>");
      row("object_name", esc(d.object_name));
      row("package_name", esc(d.package_name));
      if (d.method_name) row("method_name", esc(d.method_name));
      if (d.parent) row("parent", esc(d.parent));
      row("signature", esc("(" + (d.signature.params || []).join(", ") + ") " +
        ((d.signature.results || []).join(", ") || "")));
      row("pos", d.pos ? esc(file.path + ":" + d.pos.line + ":" + d.pos.column) : null);
      row("params", (d.params || []).map(function (p) {
        return '<span class="reg">' + esc(p.name) + "</span> " + esc(p.type);
      }).join('<span class="nmeta">, </span>'));
      if (d.free_vars && d.free_vars.length)
        row("free_vars", d.free_vars.map(function (p) {
          return '<span class="reg">' + esc(p.name) + "</span> " + esc(p.type); }).join(", "));
      if (d.locals && d.locals.length)
        row("locals", d.locals.map(function (p) { return esc(p.name) + " " + esc(p.type); }).join(", "));
      row("synthetic", String(!!d.synthetic));
      row("blocks", String(d.blocks.length));
    } else if (rec.kind === "block") {
      row("index", String(d.index));
      row("comment", esc(d.comment));
      row("preds", d.preds.length ? d.preds.map(function (p) { return "b" + p; }).join(", ") : null);
      row("succs", d.succs.length ? d.succs.map(function (p) { return "b" + p; }).join(", ") : null);
      row("instrs", String(d.instrs.length));
    } else if (rec.kind === "type") {
      row("name", esc(d.name)); row("kind", esc(d.kind));
      row("underlying_type", esc(d.underlying));
      row("pos", d.pos ? esc(file.path + ":" + d.pos.line + ":" + d.pos.column) : null);
      row("fields", String(d.fields.length));
    } else if (rec.kind === "global") {
      row("name", "@" + esc(d.name)); row("type", esc(d.type));
      row("pos", d.pos ? esc(file.path + ":" + d.pos.line + ":" + d.pos.column) : null);
      if (d.synthetic) row("synthetic", "true");
    } else if (rec.kind === "field") {
      row("name", esc(d.name)); row("type", esc(d.type)); row("tag", esc(d.tag));
    } else {
      row("name", esc(d.name)); row("language", esc(d.language));
      row("imports", (d.imports || []).map(esc).join(", "));
    }

    var cls = rec.kind === "instr" ? classify(rec.data) : null;
    sum.innerHTML = '<span class="kind ' + (rec.kind === "func" ? "func" : rec.kind === "block" ? "block" :
      rec.kind === "type" ? "type" : "") + '">' + esc(rec.kind) + "</span> " +
      '<span class="mono">' + esc(rec.label) + "</span>" +
      (rec.line ? ' <span class="nmeta">L' + rec.line + "</span>" : ' <span class="nopos-tag">no pos</span>') +
      (cls ? ' <span class="sinkflag' + (cls.kind === "source" ? " srcflag" : "") +
        '" title="' + esc(cls.rule + " \u00b7 " + cls.pattern) + '">' +
        (cls.kind === "source" ? "source" : "sink") + "</span>" : "");
    box.innerHTML = "<dl>" + rows.map(function (r) {
      return "<dt>" + r[0] + "</dt><dd>" + r[1] + "</dd>"; }).join("") + "</dl>";
  }

  /* ── clipboard popover ─────────────────────────────────────────────── */
  var pop = null;
  function closeCopy() { if (pop) { pop.remove(); pop = null; } }
  /* Build a glob that still matches under the real matcher: keep the member and
     (for a method) the receiver type, wildcard the module path. */
  function globFor(callee) {
    var m = /^([a-z]+):(.*)$/.exec(callee);
    if (!m) return callee;
    var lang = m[1], rest = m[2];
    var paren = /^\(\*?(.+)\)\.([A-Za-z_]\w*)$/.exec(rest);
    if (paren) {
      var inner = paren[1], member = paren[2];
      var dot = inner.lastIndexOf(".");
      var pkg = dot === -1 ? "" : inner.slice(0, dot);
      var typ = dot === -1 ? inner : inner.slice(dot + 1);
      var seg = pkg.split("/").pop().split(".")[0] || pkg;
      return lang + ":*" + seg + "*." + typ + "*." + member;
    }
    var dot2 = rest.lastIndexOf(".");
    if (dot2 === -1) return callee;
    var pkg2 = rest.slice(0, dot2), mem2 = rest.slice(dot2 + 1);
    if (pkg2.indexOf("/") === -1 && pkg2.indexOf(".") === -1) return callee; // stdlib: exact
    var tailSeg = pkg2.split("/").pop();
    return lang + ":*" + tailSeg + "." + mem2;
  }
  function openCopy(argEl, i) {
    var rec = nodes[i];
    if (!rec || rec.kind !== "instr" || !rec.data.call || !rec.data.call.callee) return;
    var idx = argEl.getAttribute("data-arg");
    var callee = rec.data.call.callee;
    var isRecv = idx === "recv";
    var suffix = isRecv ? "" : "#" + idx;
    var exact = callee + suffix, globbed = globFor(callee) + suffix;
    var cls = classify(rec.data);
    closeCopy();
    pop = document.createElement("div");
    pop.className = "copypop";
    pop.innerHTML = '<div class="t">' + (isRecv ? "Receiver \u2014 outside logical numbering"
        : "Pattern \u00b7 logical arg #" + idx) + "</div>" +
      '<button class="opt" type="button" data-v="' + esc(exact) + '"><span class="lab">exact</span>' +
        esc(exact) + "</button>" +
      (globbed !== exact ? '<button class="opt" type="button" data-v="' + esc(globbed) +
        '"><span class="lab">globbed \u00b7 survives a version bump</span>' + esc(globbed) + "</button>" : "") +
      '<div class="hint">' + (isRecv
        ? "A rule pins arguments only. The receiver is args[0] of a static method call, so this call\u2019s first real argument is #0."
        : (cls && cls.kind === "source"
            ? "This callee is already a source in the shipped packs. The same pattern form works in sources, sinks, propagators and sanitizers."
            : "Pins taint to this argument, so a parameterized call stays clean.")) + "</div>";
    document.body.appendChild(pop);
    var r = argEl.getBoundingClientRect();
    pop.style.left = Math.max(8, Math.min(window.innerWidth - 352, r.left - 12)) + "px";
    var below = r.bottom + 8;
    pop.style.top = (below + pop.offsetHeight > window.innerHeight - 8
      ? Math.max(8, r.top - pop.offsetHeight - 8) : below) + "px";
    $$(".opt", pop).forEach(function (b) {
      b.addEventListener("click", function () {
        var v = b.getAttribute("data-v");
        if (navigator.clipboard) navigator.clipboard.writeText(v).catch(function () {});
        $("#pattern").value = v; pattern = v;
        b.querySelector(".lab").textContent = "copied";
        applyPattern();
        setTimeout(closeCopy, 380);
      });
    });
  }
  document.addEventListener("click", function (e) {
    if (pop && !pop.contains(e.target) && !(e.target.closest && e.target.closest(".arg"))) closeCopy();
  });

  /* ── pattern tester ────────────────────────────────────────────────
     The match itself runs server-side on internal/rules, so `#0,1` specs and
     the shape-classified glob walk are the engine's, not a second copy. What
     stays here is only the rendering of the answer. */
  var matchSeq = 0, matchTimer = null;

  function requestMatch() {
    var p = pattern.trim(), seq = ++matchSeq;
    if (!p || !file) { matched = null; renderMatches(p, null); renderIR(); return; }
    api("/api/match", { file: file.id, pattern: p }).then(function (r) {
      if (seq !== matchSeq) return; // a later keystroke already won
      matched = r;
      renderMatches(p, r);
      renderIR();
    }).catch(function (e) {
      if (seq !== matchSeq) return;
      matched = null;
      $("#pat-res").innerHTML = "<b>\u2014</b>";
      $("#pat-res").className = "res none";
      $("#pat-matches").innerHTML = '<div class="nomatch">' + esc(String(e)) + "</div>";
    });
  }
  function applyPattern() {
    clearTimeout(matchTimer);
    matchTimer = setTimeout(requestMatch, MATCH_DEBOUNCE);
  }

  /* Marks the nodes the server matched, so renderIR can paint them. */
  function markMatches() {
    var ords = {};
    if (matched) (matched.matches || []).forEach(function (m) { ords[m.ord] = true; });
    nodes.forEach(function (rec) {
      rec.match = !!(rec.kind === "instr" && rec.data.ord != null && ords[rec.data.ord]);
    });
  }

  function renderMatches(p, r) {
    var res = $("#pat-res"), box = $("#pat-matches");
    markMatches();
    if (!p) { res.textContent = ""; res.className = "res"; box.innerHTML = ""; return; }
    if (noModule) {
      res.innerHTML = "<b>\u2014</b> \u00b7 no gIR loaded";
      res.className = "res none";
      box.innerHTML = '<div class="nomatch">This file produced no gIR, so no pattern can be tested against it.</div>';
      return;
    }
    if (!r) { res.textContent = ""; res.className = "res"; box.innerHTML = ""; return; }
    var n = r.count || 0, hits = r.matches || [];
    var wrongLang = !!(r.patternLang && r.moduleLang && r.patternLang !== r.moduleLang);
    if (wrongLang && !n) {
      res.innerHTML = "<b>0</b> \u00b7 " + esc(r.patternLang) + ": pattern, " + esc(r.moduleLang) + " module";
      res.className = "res none";
    } else {
      /* The pinned indices are only known from a hit, so a zero-match pattern
         must not claim one way or the other. */
      res.innerHTML = "<b>" + n + "</b> match" + (n === 1 ? "" : "es") +
        (!n ? "" : r.pinned && r.pinned.length ? " \u00b7 pinned #" + r.pinned.join(", #")
                                               : " \u00b7 no #idx: every argument");
      res.className = "res" + (n === 0 ? " none" : "");
    }
    if (!n) {
      box.innerHTML = '<div class="nomatch">' + (wrongLang
        ? "This pattern targets <b>" + esc(r.patternLang) + "</b> but the loaded module is <b>" +
          esc(r.moduleLang) + "</b>, so it cannot match here \u2014 open a " + esc(r.patternLang) +
          " file to test it. A rule also needs <code>languages: [" + esc(r.moduleLangName || r.moduleLang) +
          "]</code> to agree with its patterns."
        : "Nothing in this module matches. As a rule entry this would load, lint clean, and never fire.") +
        "</div>";
      return;
    }
    box.innerHTML = hits.map(function (m) {
      var i = byOrd[m.ord];
      if (i == null) return "";
      var rec = nodes[i];
      return '<button type="button" data-node="' + i + '"><span>' + esc(rec.fn.object_name) +
        " \u00b7 " + esc(rec.data.name || OPS[rec.data.op]) + "</span>" +
        (rec.line ? '<span class="ln">L' + rec.line + "</span>" : "") +
        (m.pinned ? '<span class="pin">#' + m.pinnedIdx + " " + esc(shortStr(m.pinned, 20)) + "</span>" : "") +
        "</button>";
    }).join("") + (n > hits.length ? '<div class="nomatch">+' + (n - hits.length) + " more</div>" : "");
    $$("button", box).forEach(function (b) {
      b.addEventListener("click", function () {
        var i = +b.getAttribute("data-node");
        pickNode(i); revealNode(i);
      });
    });
  }

  /* ── presets: the shipped patterns that actually hit this scan ─────── */
  function renderPresets() {
    if (!presets) return;
    var groups = [["sinks", presets.sinks], ["sources", presets.sources], ["propagator", presets.propagators]];
    var html = "";
    groups.forEach(function (g) {
      if (!g[1] || !g[1].length) return;
      html += '<span class="plabel">' + g[0] + "</span>";
      g[1].forEach(function (p) {
        html += '<button type="button" data-p="' + esc(p) + '">' + esc(shortStr(p, 34)) + "</button>";
      });
    });
    var host = $("#presets");
    host.innerHTML = html;
    $$("button", host).forEach(function (b) {
      b.addEventListener("click", function () {
        pattern = b.getAttribute("data-p");
        $("#pattern").value = pattern;
        applyPattern();
      });
    });
  }

  /* ── file tree: real nesting, one collapsible node per path segment ──
     Folders come from splitting each file's path, so the tree shows the repo
     shape (test/go/gin_gorm/…) rather than one flat row per directory. Open
     state is keyed by folder path and persisted. */
  var dirOpen = {};
  try { dirOpen = JSON.parse(localStorage.getItem("gir-dirs") || "{}"); } catch (e) { dirOpen = {}; }
  var treeFilter = "";

  /* Case-insensitive substring match on the file name, falling back to the full
     path so "test/go" works too. While a filter is active every surviving folder
     is forced open and empty ones are pruned, so the result is the matches and
     nothing else. */
  function matchesFilter(name, path) {
    if (!treeFilter) return true;
    var q = treeFilter.toLowerCase();
    return name.toLowerCase().indexOf(q) !== -1 || path.toLowerCase().indexOf(q) !== -1;
  }
  function markName(name) {
    if (!treeFilter) return esc(name);
    var i = name.toLowerCase().indexOf(treeFilter.toLowerCase());
    if (i === -1) return esc(name);
    return esc(name.slice(0, i)) + '<span class="hl">' + esc(name.slice(i, i + treeFilter.length)) +
      "</span>" + esc(name.slice(i + treeFilter.length));
  }

  function buildTree() {
    var rootNode = { dirs: {}, files: [] };
    function place(entry) {
      var parts = entry.path.split("/");
      var name = parts.pop();
      var node = rootNode, prefix = "";
      parts.forEach(function (seg) {
        prefix = prefix ? prefix + "/" + seg : seg;
        if (!node.dirs[seg]) node.dirs[seg] = { name: seg, path: prefix, dirs: {}, files: [] };
        node = node.dirs[seg];
      });
      node.files.push({ entry: entry, name: name });
    }
    files.forEach(function (f) { place(f); });
    return rootNode;
  }

  function keptFiles(node) {
    return node.files.filter(function (f) { return matchesFilter(f.name, f.entry.path); });
  }
  function countFiles(node) {
    var n = keptFiles(node).length;
    Object.keys(node.dirs).forEach(function (k) { n += countFiles(node.dirs[k]); });
    return n;
  }

  function renderTree() {
    var rootNode = buildTree();
    var total = 0;
    var html = '<div class="tree">';
    (function walk(node, depth) {
      Object.keys(node.dirs).sort().forEach(function (k) {
        var d = node.dirs[k];
        if (treeFilter && countFiles(d) === 0) return; // prune empty branches
        if (dirOpen[d.path] === undefined) dirOpen[d.path] = true;
        var isOpen = treeFilter ? true : !!dirOpen[d.path];
        html += '<button class="dir" type="button" data-dir="' + esc(d.path) +
          '" aria-expanded="' + isOpen + '" style="padding-left:' + (8 + depth * 12) + 'px">' +
          '<span class="tw' + (isOpen ? " on" : "") + '"></span>' +
          '<span class="dn">' + esc(d.name) + "</span>" +
          '<span class="dc">' + countFiles(d) + "</span></button>";
        if (isOpen) walk(d, depth + 1);
      });
      keptFiles(node).sort(function (a, b) { return a.name.localeCompare(b.name); }).forEach(function (f) {
        var e = f.entry, cur = file && e.id === file.id;
        total++;
        html += '<button class="filerow" type="button" data-file="' + e.id + '"' +
          (e.state ? ' data-state="' + e.state + '"' : "") +
          (cur ? ' aria-current="true"' : "") +
          ' style="padding-left:' + (8 + depth * 12 + 13) + 'px" title="' + esc(e.path) +
          '"><span class="nm">' + markName(f.name) + "</span>" +
          (e.findings ? '<span class="ct">' + e.findings + "</span>" : "") +
          (e.state ? '<span class="ct warn" title="' + esc(e.stateDetail || EMPTY[e.state].t) + '">!</span>' : "") +
          "</button>";
      });
    })(rootNode, 0);
    if (treeFilter && !total) {
      html += '<div class="noresult">No file matches “' + esc(treeFilter) + '”</div>';
    }
    $("#tree").innerHTML = html + "</div>";
    var tc = $("#tree-count");
    if (tc) tc.textContent = treeFilter ? total + " of " + files.length : String(files.length);
    var clr = $("#tree-filter-clear");
    if (clr) clr.hidden = !treeFilter;
    $$("#tree .dir").forEach(function (b) {
      b.addEventListener("click", function () {
        var d = b.getAttribute("data-dir");
        dirOpen[d] = !dirOpen[d];
        try { localStorage.setItem("gir-dirs", JSON.stringify(dirOpen)); } catch (e) {}
        renderTree();
      });
    });
    $$("#tree .filerow").forEach(function (b) {
      b.addEventListener("click", function () {
        selectFile(b.getAttribute("data-file"));
      });
    });
  }
  function markCurrent(id) {
    $$("#tree .filerow").forEach(function (b) {
      b.setAttribute("aria-current", String(b.getAttribute("data-file") === id));
    });
  }
  function stateIcon(kind) {
    return kind === "warn"
      ? '<svg class="sicon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"><path d="M12 3.5 22 20.5H2z"/><path d="M12 10v4.5M12 17.6v.1"/></svg>'
      : '<svg class="sicon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/></svg>';
  }
  var noModule = false;
  function showEmpty(state, f) {
    var e = EMPTY[state] || EMPTY["empty-failed"];
    selNode = null; fanout = []; nodes = []; byLine = {}; byOrd = {};
    noModule = true;
    file = f || null;
    $("#file-path").textContent = f ? f.path : "\u2014";
    $("#code").innerHTML = '<div class="statebox">' + stateIcon(e.icon) + "<h3>" + esc(e.t) + "</h3><p>" +
      esc((f && f.stateDetail) || e.d) + "</p></div>";
    $("#ir").innerHTML = '<div class="statebox sm">' + stateIcon(e.icon) + "<p>No gIR for this file.</p></div>";
    $("#ir").style.height = "";
    $("#ir-count").textContent = "0 nodes";
    $("#stepper").hidden = true;
    $("#virt-note").hidden = true;
    renderInspector(null);
    matched = null;
    renderMatches(pattern.trim(), null);
  }
  function skeleton(n) {
    var out = '<div class="skel">';
    for (var i = 0; i < n; i++) out += "<i></i>";
    return out + "</div>";
  }
  function selectFile(id) {
    var entry = files.filter(function (x) { return x.id === id; })[0];
    if (!entry) return;
    markCurrent(id);
    if (entry.state) { showEmpty(entry.state, entry); return; }
    $("#code").innerHTML = skeleton(14);
    $("#ir").innerHTML = skeleton(18);
    $("#ir").style.height = "";
    $("#ir-count").textContent = "loading\u2026";
    $("#stepper").hidden = true;
    renderInspector(null);
    var seq = ++fileSeq;
    api("/api/file?p=" + encodeURIComponent(id)).then(function (f) {
      if (seq !== fileSeq) return; // a later click already won
      file = f;
      noModule = false;
      selNode = null; fanout = []; fanIdx = 0;
      $("#file-path").textContent = f.path;
      build(); renderCode(); paint(); bootSelect();
      requestMatch();
    }).catch(function (e) { if (seq === fileSeq) fail(e.message); });
  }
  var fileSeq = 0;

  /* ── resizable columns ─────────────────────────────────────────────── */
  var COLS_KEY = "gir-cols";
  var widths = { a: 216, b: 420 };
  try {
    var saved = JSON.parse(localStorage.getItem(COLS_KEY) || "null");
    if (saved && saved.a > 80 && saved.b > 160) widths = saved;
  } catch (e) {}
  var MIN_A = 130, MIN_B = 220, MIN_IR = 320;
  /* Saved widths come from whatever viewport they were dragged in, so they are
     clamped on every apply — not just during a drag — and the gIR column keeps a
     floor. Without this a narrower window silently squeezes column 3 to nothing. */
  function clampCols() {
    var total = $("#cols").clientWidth || window.innerWidth;
    var a = Math.max(MIN_A, Math.min(widths.a, total - MIN_B - MIN_IR - 2));
    var b = Math.max(MIN_B, Math.min(widths.b, total - a - MIN_IR - 2));
    if (total - a - b - 2 < MIN_IR) a = Math.max(MIN_A, total - b - MIN_IR - 2);
    widths.a = Math.round(a); widths.b = Math.round(b);
  }
  function applyCols() {
    clampCols();
    $("#cols").style.gridTemplateColumns = widths.a + "px 1px " + widths.b + "px 1px minmax(0,1fr)";
  }
  applyCols();
  window.addEventListener("resize", function () { applyCols(); renderIR(); });
  $$(".resizer").forEach(function (h) {
    h.addEventListener("pointerdown", function (e) {
      e.preventDefault();
      var which = h.getAttribute("data-resize");
      var startX = e.clientX, w0 = widths[which];
      var total = $("#cols").clientWidth;
      h.setPointerCapture(e.pointerId);
      document.body.classList.add("resizing");
      function move(ev) {
        var d = ev.clientX - startX;
        widths[which] = w0 + d;
        applyCols();
      }
      function up() {
        h.removeEventListener("pointermove", move);
        h.removeEventListener("pointerup", up);
        document.body.classList.remove("resizing");
        try { localStorage.setItem(COLS_KEY, JSON.stringify(widths)); } catch (e) {}
        renderIR();
      }
      h.addEventListener("pointermove", move);
      h.addEventListener("pointerup", up);
    });
    h.addEventListener("dblclick", function () {
      widths = { a: 216, b: 420 };
      applyCols();
      try { localStorage.setItem(COLS_KEY, JSON.stringify(widths)); } catch (e) {}
      renderIR();
    });
  });

  /* ── wiring ────────────────────────────────────────────────────────── */
  $("#ir-wrap").addEventListener("click", function (e) {
    var row = e.target.closest(".nrow");
    if (!row) return;
    var i = +row.getAttribute("data-node");
    var arg = e.target.closest(".arg");
    if (arg) { e.stopPropagation(); openCopy(arg, i); return; }
    var blk = e.target.closest(".blk");
    if (blk) {
      e.stopPropagation();
      var want = blk.getAttribute("data-goblock").replace(/^b/, "");
      var fnName = nodes[i].fn && nodes[i].fn.name;
      for (var k = 0; k < nodes.length; k++) {
        if (nodes[k].kind === "block" && nodes[k].fn && nodes[k].fn.name === fnName &&
            String(nodes[k].data.index) === want) { pickNode(k); revealNode(k); return; }
      }
      return;
    }
    if (nodes[i].kids.length) open[i] = !open[i];
    pickNode(i);
  });
  $("#code").addEventListener("click", function (e) {
    var el = e.target.closest(".cline.has");
    if (el) pickLine(+el.getAttribute("data-line"));
  });
  $("#ir-wrap").addEventListener("scroll", function () { if (virt) renderIR(); });
  $("#pattern").addEventListener("input", function () { pattern = this.value; applyPattern(); });
  var filterInput = $("#tree-filter"), filterTimer = null;
  filterInput.addEventListener("input", function () {
    var v = this.value;
    clearTimeout(filterTimer);
    filterTimer = setTimeout(function () { treeFilter = v.trim(); renderTree(); }, 90);
  });
  filterInput.addEventListener("keydown", function (e) {
    if (e.key === "Escape") { this.value = ""; treeFilter = ""; renderTree(); this.blur(); }
  });
  $("#tree-filter-clear").addEventListener("click", function () {
    filterInput.value = ""; treeFilter = ""; renderTree(); filterInput.focus();
  });
  $("#step-prev").addEventListener("click", function () { step(-1); });
  $("#step-next").addEventListener("click", function () { step(1); });
  var WRAP_KEY = "gir-wrap";
  var wrapBtn = $("#wrap-toggle");
  function paintWrap(on) {
    document.body.classList.toggle("wrap-src", on);
    wrapBtn.setAttribute("aria-pressed", String(on));
  }
  try { paintWrap(localStorage.getItem(WRAP_KEY) === "1"); } catch (e) { paintWrap(false); }
  wrapBtn.addEventListener("click", function () {
    var on = !document.body.classList.contains("wrap-src");
    paintWrap(on);
    try { localStorage.setItem(WRAP_KEY, on ? "1" : "0"); } catch (e) {}
  });
  $("#insp-toggle").addEventListener("click", function () {
    var c = document.body.classList.toggle("insp-collapsed");
    this.setAttribute("aria-expanded", String(!c));
  });
  document.addEventListener("keydown", function (e) {
    if (e.target.tagName === "INPUT") { if (e.key === "Escape") e.target.blur(); return; }
    if (e.key === "/") { e.preventDefault(); $("#pattern").focus(); return; }
    if (e.key === "Escape") { selNode = null; fanout = []; paint(); return; }
    if (e.key === "ArrowDown" || e.key === "j") { e.preventDefault(); step(1); }
    if (e.key === "ArrowUp" || e.key === "k") { e.preventDefault(); step(-1); }
  });

  /* ── boot ──────────────────────────────────────────────────────────── */
  /* Lands on the first flagged call, which is what a rule author came to look
     at; falls back to whatever the module starts with. */
  function bootSelect() {
    var first = null;
    for (var i = 0; i < nodes.length; i++) {
      var r = nodes[i];
      if (r.kind !== "instr" || !r.data.flag) continue;
      if (r.data.flag.kind === "sink") { pickNode(i); revealNode(i); return; }
      if (first === null) first = i;
    }
    if (first !== null) { pickNode(first); revealNode(first); return; }
    paint();
  }

  api("/api/tree").then(function (tree) {
    files = tree.files || [];
    presets = tree.presets || null;
    if (tree.version) $("#brand-version").textContent = "gIR v1 \u00b7 godzilla " + tree.version;
    /* Paths in the tree are root-relative; the root itself is the tooltip so the
       header stays short without hiding which tree is on screen. */
    if (tree.root) $("#file-path").title = tree.root;
    renderTree();
    renderPresets();
    var firstReal = files.filter(function (f) { return !f.state; })[0];
    if (firstReal) selectFile(firstReal.id);
    else if (files.length) selectFile(files[0].id);
    else {
      $("#file-path").textContent = "\u2014";
      $("#code").innerHTML = '<div class="statebox">' + stateIcon("file") + "<h3>" +
        esc(EMPTY["empty-nofile"].t) + "</h3><p>" + esc(EMPTY["empty-nofile"].d) + "</p></div>";
      $("#ir").innerHTML = '<div class="statebox sm">' + stateIcon("file") + "<p>Nothing lowered yet.</p></div>";
      $("#ir-count").textContent = "0 nodes";
      renderInspector(null);
    }
  }).catch(function (e) { fail(e.message); });
})();

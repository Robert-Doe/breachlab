# Module 14 — Decisions

## Why prototype pollution as a DOM XSS vector?
It's the hardest category to find via code review because source and sink are in separate code paths with no visible taint. PhD-level defender must understand it.

## Lab design: 4 gadgets not 1
Each gadget models a realistic pattern: deep merge util, JSON config parse, template engine, jQuery-like library. Real-world vulns are always one of these shapes.

## Server-side vs client-side pollution
All pollution in this module is client-side (JS in browser). Server-side prototype pollution (Node.js) is a different attack class — noted in tutorial but lab focuses on browser DOM XSS chain.

## Key restriction keys
Blocking only `__proto__` is insufficient; `constructor.prototype` is an alternate path. Tutorial explicitly covers all three: `__proto__`, `constructor`, `prototype`.

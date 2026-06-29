# Module 16 — Design Decisions

## Why a social network for the worm demo?
The Samy worm hit MySpace — a social platform. Replicating that context (profiles, visitors, bio fields) makes the demo structurally identical to the real incident. Worm conditions: stored XSS sink, write-back, field shown to other users.

## Why pre-seeded profiles (alice, bob, charlie, dave)?
Students can log in as different users to observe worm spread. Login as alice, set a worm payload as bio → log in as bob, visit alice's profile → bob's bio is now infected → log in as charlie, visit bob's profile → chain continues.

## Why separate case_studies/ pages instead of server-rendered content?
Case studies are reference material — historical reconstructions requiring careful prose and code annotation. They don't need server interaction; making them static HTML keeps them usable offline and lets students share them easily.

## Why include the Magecart case (supply chain) in an XSS course?
Magecart is technically a stored XSS (injected JS into a JS file). It demonstrates that the injection point doesn't have to be a user-visible form — a compromised CDN asset is an injection point. Defense (SRI) is the same class as XSS defense.

## Why no worm rate limiting?
For pedagogical clarity — the lab shows unlimited propagation. Real-world defense discussion in tutorial.html includes rate limiting as a mitigation. The DECISIONS.md makes this deliberate omission visible to instructors.

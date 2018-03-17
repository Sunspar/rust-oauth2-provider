In order of importance, with higher items needing a look first:

- fix outstanding compiler errors with respect to the uuid crate
- investigate general code flow -- can we place things in better modules?
- Move as many functions taking `String` arguments to either `&str` or a better type if context dictates
- Anything from the "Known Deviations" to bring us closer to full compliance with the RFCs
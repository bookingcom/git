At Booking.com we contribute to Git development, mainly due to git
scalability issues we run into.

We don't hard-fork git, all contributions are contributed upstream,
mainly by Ævar Arnfjörð Bjarmason and Christian Couder.

This repository contains tags representing the git version running on
Booking.com, these usually cherry-picked topics from `pu` applied on
top of git's latest release.

If the tag is really old that either means we ended up converging with
upstream and use the latest upstream vanilla release, or our script to
push things here broke.

# Debian packages

**NOTE** The direction we are going with the new backend is that of dropping debian packaging of all backend API components and move to a dockerized deployment approach.

This section lists the Debian packages used to deploy backend
components. They are built by [GitHub CI workflows](#github-ci-workflows)&thinsp;💡
and deployed using [The deployer tool](#the-deployer-tool)&thinsp;🔧. See
[Debian package build and publish](#debian-package-build-and-publish)&thinsp;💡.


#### ooni-api package
Debian package for the [API](#api)&thinsp;⚙


#### fastpath package
Debian package for the [Fastpath](#fastpath)&thinsp;⚙


#### detector package
Debian package for the
[Social media blocking event detector](#social-media-blocking-event-detector)&thinsp;⚙


#### analysis package
The `analysis` Debian package contains various tools and runs various of
systemd timers, see [Systemd timers](#systemd-timers)&thinsp;💡.


#### Analysis deployment
See [Backend component deployment](#backend-component-deployment)&thinsp;📒

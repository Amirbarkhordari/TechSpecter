"""Built-in technology signature catalog."""

from __future__ import annotations

from techspecter.fingerprinting.signatures.catalog.builder import SignatureBuilder
from techspecter.fingerprinting.signatures.catalog.patterns import ind, req_regex, ver
from techspecter.fingerprinting.signatures.categories import TechnologyCategory as Cat
from techspecter.fingerprinting.signatures.models import TechnologySignature


def build_catalog() -> list[TechnologySignature]:
    """Return all catalog-defined technology signatures."""
    return [item.build() for item in _definitions()]


def _definitions() -> list[SignatureBuilder]:
    """Define catalog signatures."""
    b = SignatureBuilder
    items: list[SignatureBuilder] = []

    # Frontend Frameworks
    items.extend(
        [
            b(
                id="react",
                name="React",
                category=Cat.FRONTEND_FRAMEWORKS,
                vendor="Meta",
                website="https://react.dev",
                priority=100,
            )
            .alias("reactjs")
            .required_rule(
                req_regex(
                    "react",
                    r"reactdom\.(createroot|createelement)|\busestate\b|react\.createelement",
                )
            )
            .optional(
                runtime=(
                    ind("createRoot", "reactdom.createroot", weight=90),
                    ind("useState", "usestate", weight=75),
                ),
                package=(ind("pkg", "react", weight=85),),
            )
            .versions(ver("react-ver", r"react[^0-9]*([0-9]+\.[0-9]+\.[0-9]+)", source="banner")),
            b(
                id="preact",
                name="Preact",
                category=Cat.FRONTEND_FRAMEWORKS,
                website="https://preactjs.com",
                priority=90,
            )
            .required_rule(req_regex("preact", r"preact|preact/compat"))
            .optional(
                runtime=(ind("preact", "preact", weight=85),),
                package=(ind("pkg", "preact", weight=80),),
            ),
            b(
                id="vue",
                name="Vue.js",
                category=Cat.FRONTEND_FRAMEWORKS,
                vendor="Evan You",
                website="https://vuejs.org",
                priority=100,
            )
            .alias("vuejs")
            .required_rule(req_regex("vue", r"vue\.createapp|@vue/|createapp\("))
            .optional(
                runtime=(ind("createApp", "vue.createapp", weight=90),),
                package=(ind("pkg", "@vue/", weight=95),),
            )
            .versions(ver("vue-ver", r"vue[^0-9]*([0-9]+\.[0-9]+\.[0-9]+)")),
            b(
                id="angular",
                name="Angular",
                category=Cat.FRONTEND_FRAMEWORKS,
                vendor="Google",
                website="https://angular.dev",
                priority=100,
            )
            .required_rule(
                req_regex("angular", r"ɵɵdefinecomponent|@angular/core|ng-version|angular\.module")
            )
            .optional(
                runtime=(ind("ivy", "ɵɵdefinecomponent", weight=95),),
                package=(ind("core", "@angular/core", weight=95),),
            )
            .negative(runtime=(ind("zone-only", "zone.js", weight=20),))
            .versions(ver("ng-ver", r"@angular/core@([0-9]+\.[0-9]+\.[0-9]+)", source="package")),
            b(
                id="svelte",
                name="Svelte",
                category=Cat.FRONTEND_FRAMEWORKS,
                website="https://svelte.dev",
                priority=95,
            )
            .required_rule(req_regex("svelte", r"sveltecomponent|svelte/internal|\.svelte"))
            .optional(
                runtime=(ind("runtime", "sveltecomponent", weight=90),),
                package=(ind("pkg", "svelte", weight=85),),
            ),
            b(
                id="solidjs",
                name="SolidJS",
                category=Cat.FRONTEND_FRAMEWORKS,
                website="https://solidjs.com",
                priority=90,
            )
            .required_rule(req_regex("solidjs", r"createsignal|solid-js|solidjs"))
            .optional(
                runtime=(ind("signal", "createsignal", weight=90),),
                package=(ind("pkg", "solid-js", weight=85),),
            ),
            b(
                id="qwik",
                name="Qwik",
                category=Cat.FRONTEND_FRAMEWORKS,
                website="https://qwik.dev",
                priority=90,
            )
            .required_rule(req_regex("qwik", r"qwik|@builder.io/qwik|q:container"))
            .optional(
                runtime=(ind("qwik", "qwik", weight=85),),
                package=(ind("pkg", "@builder.io/qwik", weight=90),),
            ),
            b(
                id="alpinejs",
                name="Alpine.js",
                category=Cat.JAVASCRIPT_LIBRARIES,
                website="https://alpinejs.dev",
                priority=85,
            )
            .required_rule(req_regex("alpinejs", r"x-data|alpinejs|@alpinejs"))
            .optional(
                html=(ind("x-data", "x-data", weight=85),),
                runtime=(ind("alpine", "alpine", weight=80),),
            ),
            b(
                id="htmx",
                name="htmx",
                category=Cat.JAVASCRIPT_LIBRARIES,
                website="https://htmx.org",
                priority=85,
            )
            .required_rule(req_regex("htmx", r"htmx\.org|hx-get|hx-post|htmx/"))
            .optional(
                html=(ind("hx", "hx-get", weight=85),), runtime=(ind("lib", "htmx", weight=80),)
            ),
            b(
                id="lit",
                name="Lit",
                category=Cat.FRONTEND_FRAMEWORKS,
                website="https://lit.dev",
                priority=85,
            )
            .required_rule(req_regex("lit", r"lit-element|lit-html|@lit/"))
            .optional(
                package=(ind("pkg", "lit-element", weight=85),),
                runtime=(ind("lit", "lit-html", weight=80),),
            ),
            b(
                id="stencil",
                name="Stencil",
                category=Cat.FRONTEND_FRAMEWORKS,
                vendor="Ionic",
                website="https://stenciljs.com",
                priority=80,
            )
            .required_rule(req_regex("stencil", r"@stencil/core|stenciljs"))
            .optional(
                package=(ind("pkg", "@stencil/core", weight=90),),
            ),
        ],
    )

    # Meta Frameworks
    items.extend(
        [
            b(
                id="nextjs",
                name="Next.js",
                category=Cat.META_FRAMEWORKS,
                vendor="Vercel",
                website="https://nextjs.org",
                priority=110,
            )
            .depends("react")
            .required_rule(req_regex("nextjs", r"__next_data__|/_next/static/|buildmanifest"))
            .optional(
                runtime=(ind("data", "__next_data__", weight=95),),
                manifest=(ind("manifest", "buildmanifest", weight=90),),
            )
            .versions(ver("next-ver", r"next[^0-9]*([0-9]+\.[0-9]+\.[0-9]+)")),
            b(
                id="nuxt",
                name="Nuxt",
                category=Cat.META_FRAMEWORKS,
                website="https://nuxt.com",
                priority=105,
            )
            .depends("vue")
            .required_rule(req_regex("nuxt", r"__nuxt__|__nuxt_manifest__|nuxt\.config"))
            .optional(
                runtime=(ind("runtime", "__nuxt__", weight=95),),
                manifest=(ind("manifest", "__nuxt_manifest__", weight=90),),
            ),
            b(
                id="sveltekit",
                name="SvelteKit",
                category=Cat.META_FRAMEWORKS,
                website="https://kit.svelte.dev",
                priority=100,
            )
            .depends("svelte")
            .required_rule(req_regex("sveltekit", r"@sveltejs/kit|__sveltekit|sveltekit"))
            .optional(
                package=(ind("pkg", "@sveltejs/kit", weight=95),),
            ),
            b(
                id="astro",
                name="Astro",
                category=Cat.STATIC_SITE_GENERATORS,
                website="https://astro.build",
                priority=95,
            )
            .required_rule(req_regex("astro", r"\bastro\b|data-astro|astro/"))
            .optional(
                runtime=(ind("astro", "astro", weight=85),),
                html=(ind("data", "data-astro", weight=80),),
            ),
            b(
                id="remix",
                name="Remix",
                category=Cat.META_FRAMEWORKS,
                website="https://remix.run",
                priority=100,
            )
            .depends("react")
            .required_rule(req_regex("remix", r"@remix-run|remix\.run|__remix"))
            .optional(
                package=(ind("pkg", "@remix-run/react", weight=95),),
            ),
            b(
                id="gatsby",
                name="Gatsby",
                category=Cat.STATIC_SITE_GENERATORS,
                website="https://gatsbyjs.com",
                priority=95,
            )
            .depends("react")
            .required_rule(req_regex("gatsby", r"gatsby|___loader|gatsby-plugin"))
            .optional(
                runtime=(ind("loader", "___loader", weight=90),),
                package=(ind("pkg", "gatsby", weight=85),),
            ),
        ],
    )

    # Bundlers & Build Tools
    items.extend(
        [
            b(
                id="webpack",
                name="Webpack",
                category=Cat.BUNDLERS,
                website="https://webpack.js.org",
                priority=75,
            )
            .required_rule(req_regex("webpack", r"__webpack_require__|webpackchunk|webpackjsonp"))
            .optional(
                bundle=(
                    ind("runtime", "__webpack_require__", weight=90),
                    ind("chunk", "webpackchunk", weight=80),
                )
            ),
            b(
                id="vite",
                name="Vite",
                category=Cat.BUNDLERS,
                website="https://vitejs.dev",
                priority=80,
            )
            .required_rule(req_regex("vite", r"__vite__|import\.meta\.env|vite/dist"))
            .optional(
                bundle=(ind("runtime", "__vite__", weight=90),),
                manifest=(ind("manifest", "vite.manifest", weight=85),),
            ),
            b(
                id="rollup",
                name="Rollup",
                category=Cat.BUNDLERS,
                website="https://rollupjs.org",
                priority=70,
            )
            .required_rule(req_regex("rollup", r"rollupversion|\brollup\b"))
            .optional(
                bundle=(ind("rollup", "rollupversion", weight=85),),
            ),
            b(
                id="parcel",
                name="Parcel",
                category=Cat.BUNDLERS,
                website="https://parceljs.org",
                priority=70,
            )
            .required_rule(req_regex("parcel", r"parcelrequire|\bparcel\b"))
            .optional(
                bundle=(ind("runtime", "parcelrequire", weight=85),),
            ),
            b(
                id="rspack",
                name="Rspack",
                category=Cat.BUNDLERS,
                website="https://rspack.dev",
                priority=75,
            )
            .required_rule(req_regex("rspack", r"__rspack_require__|rspack"))
            .optional(
                bundle=(ind("runtime", "__rspack_require__", weight=90),),
            ),
            b(id="turbopack", name="Turbopack", category=Cat.BUNDLERS, vendor="Vercel", priority=75)
            .required_rule(req_regex("turbopack", r"turbopack|__turbopack__"))
            .optional(
                bundle=(ind("runtime", "turbopack", weight=90),),
            ),
        ],
    )

    # CSS & Component Libraries
    items.extend(
        [
            b(
                id="tailwindcss",
                name="Tailwind CSS",
                category=Cat.CSS_FRAMEWORKS,
                website="https://tailwindcss.com",
                priority=85,
            )
            .required_rule(req_regex("tailwindcss", r"tailwindcss|tailwind\.config|@tailwind"))
            .optional(
                package=(ind("pkg", "tailwindcss", weight=90),),
                content=(ind("class", "tailwind", weight=70),),
            ),
            b(
                id="bootstrap",
                name="Bootstrap",
                category=Cat.CSS_FRAMEWORKS,
                website="https://getbootstrap.com",
                priority=85,
            )
            .required_rule(req_regex("bootstrap", r"bootstrap(\.min)?\.(css|js)|getbootstrap"))
            .optional(
                html=(ind("css", "bootstrap.min.css", weight=85),),
                package=(ind("pkg", "bootstrap", weight=80),),
            ),
            b(
                id="bulma",
                name="Bulma",
                category=Cat.CSS_FRAMEWORKS,
                website="https://bulma.io",
                priority=75,
            )
            .required_rule(req_regex("bulma", r"bulma(\.min)?\.css|bulma\.io"))
            .optional(
                html=(ind("css", "bulma", weight=85),),
            ),
            b(
                id="foundation",
                name="Foundation",
                category=Cat.CSS_FRAMEWORKS,
                website="https://get.foundation",
                priority=70,
            )
            .required_rule(req_regex("foundation", r"foundation\.min\.(css|js)|get\.foundation"))
            .optional(
                html=(ind("css", "foundation", weight=80),),
            ),
            b(
                id="mui",
                name="Material UI",
                category=Cat.COMPONENT_LIBRARIES,
                vendor="MUI",
                website="https://mui.com",
                priority=85,
            )
            .alias("material-ui")
            .required_rule(req_regex("mui", r"@mui/material|material-ui|@material-ui"))
            .optional(
                package=(ind("pkg", "@mui/material", weight=95),),
            ),
            b(
                id="chakra-ui",
                name="Chakra UI",
                category=Cat.COMPONENT_LIBRARIES,
                website="https://chakra-ui.com",
                priority=80,
            )
            .required_rule(req_regex("chakra-ui", r"@chakra-ui|chakra-ui"))
            .optional(
                package=(ind("pkg", "@chakra-ui/react", weight=95),),
            ),
            b(
                id="antd",
                name="Ant Design",
                category=Cat.COMPONENT_LIBRARIES,
                website="https://ant.design",
                priority=85,
            )
            .alias("ant-design")
            .required_rule(req_regex("antd", r"antd|ant-design|@ant-design"))
            .optional(
                package=(ind("pkg", "antd", weight=95),),
            ),
            b(
                id="mantine",
                name="Mantine",
                category=Cat.COMPONENT_LIBRARIES,
                website="https://mantine.dev",
                priority=80,
            )
            .required_rule(req_regex("mantine", r"@mantine/|mantine"))
            .optional(
                package=(ind("pkg", "@mantine/core", weight=95),),
            ),
            b(
                id="emotion",
                name="Emotion",
                category=Cat.JAVASCRIPT_LIBRARIES,
                website="https://emotion.sh",
                priority=75,
            )
            .required_rule(req_regex("emotion", r"@emotion/react|@emotion/styled|emotion"))
            .optional(
                package=(ind("pkg", "@emotion/react", weight=90),),
            ),
            b(
                id="styled-components",
                name="styled-components",
                category=Cat.JAVASCRIPT_LIBRARIES,
                website="https://styled-components.com",
                priority=80,
            )
            .required_rule(req_regex("styled-components", r"styled-components|styled\.components"))
            .optional(
                package=(ind("pkg", "styled-components", weight=95),),
                runtime=(ind("sc", "styled-components", weight=85),),
            ),
            b(
                id="goober",
                name="Goober",
                category=Cat.JAVASCRIPT_LIBRARIES,
                website="https://github.com/cristianbote/goober",
                priority=70,
            )
            .required_rule(req_regex("goober", r"goober|goober/dist"))
            .optional(
                package=(ind("pkg", "goober", weight=90),),
            ),
        ],
    )

    # CMS
    items.extend(
        [
            b(
                id="wordpress",
                name="WordPress",
                category=Cat.CMS,
                website="https://wordpress.org",
                priority=90,
            )
            .required_rule(req_regex("wordpress", r"wp-content|wp-includes|wordpress"))
            .optional(
                header=(ind("header", "wordpress", weight=90),),
                content=(ind("path", "wp-content", weight=80),),
            )
            .versions(
                ver("wp-ver", r"wordpress[^0-9]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", source="metadata")
            ),
            b(
                id="woocommerce",
                name="WooCommerce",
                category=Cat.CMS,
                website="https://woocommerce.com",
                priority=85,
            )
            .depends("wordpress")
            .required_rule(
                req_regex("woocommerce", r"woocommerce|wc-ajax|wp-content/plugins/woocommerce")
            )
            .optional(
                content=(ind("plugin", "woocommerce", weight=90),),
            ),
            b(
                id="drupal",
                name="Drupal",
                category=Cat.CMS,
                website="https://drupal.org",
                priority=85,
            )
            .required_rule(req_regex("drupal", r"drupal|sites/default/files|x-drupal"))
            .optional(
                header=(ind("header", "x-drupal", weight=90),),
                metadata=(ind("meta", "drupal", weight=85),),
            ),
            b(
                id="joomla",
                name="Joomla",
                category=Cat.CMS,
                website="https://joomla.org",
                priority=80,
            )
            .required_rule(req_regex("joomla", r"joomla|/media/jui/|option=com_"))
            .optional(
                content=(ind("path", "joomla", weight=85),),
            ),
            b(id="ghost", name="Ghost", category=Cat.CMS, website="https://ghost.org", priority=80)
            .required_rule(req_regex("ghost", r"ghost\.org|/ghost/api/|x-ghost"))
            .optional(
                header=(ind("header", "ghost", weight=85),),
            ),
            b(
                id="magento",
                name="Magento",
                category=Cat.CMS,
                vendor="Adobe",
                website="https://magento.com",
                priority=85,
            )
            .required_rule(req_regex("magento", r"magento|mage/cookies|x-magento"))
            .optional(
                header=(ind("header", "magento", weight=90),),
                content=(ind("path", "magento", weight=85),),
            ),
            b(
                id="shopify",
                name="Shopify",
                category=Cat.CMS,
                website="https://shopify.com",
                priority=90,
            )
            .required_rule(req_regex("shopify", r"cdn\.shopify\.com|shopify\.com|x-shopid"))
            .optional(
                header=(ind("header", "shopify", weight=90),),
                content=(ind("cdn", "cdn.shopify.com", weight=95),),
            ),
        ],
    )

    # Backend Frameworks
    items.extend(
        [
            b(
                id="laravel",
                name="Laravel",
                category=Cat.BACKEND_FRAMEWORKS,
                website="https://laravel.com",
                priority=85,
            )
            .required_rule(req_regex("laravel", r"laravel_session|x-powered-by.*laravel"))
            .optional(
                header=(
                    ind("header", "laravel", weight=90),
                    ind("cookie", "laravel_session", weight=85),
                )
            ),
            b(
                id="symfony",
                name="Symfony",
                category=Cat.BACKEND_FRAMEWORKS,
                website="https://symfony.com",
                priority=80,
            )
            .required_rule(req_regex("symfony", r"symfony|x-debug-token|sf_redirect"))
            .optional(
                header=(ind("debug", "x-debug-token", weight=90),),
            ),
            b(id="codeigniter", name="CodeIgniter", category=Cat.BACKEND_FRAMEWORKS, priority=75)
            .required_rule(req_regex("codeigniter", r"ci_session|codeigniter"))
            .optional(
                header=(ind("cookie", "ci_session", weight=85),),
            ),
            b(
                id="yii",
                name="Yii",
                category=Cat.BACKEND_FRAMEWORKS,
                website="https://yiiframework.com",
                priority=75,
            )
            .required_rule(req_regex("yii", r"yii\.js|csrf-token.*yii|yiiframework"))
            .optional(
                content=(ind("js", "yii.js", weight=85),),
            ),
            b(
                id="cakephp",
                name="CakePHP",
                category=Cat.BACKEND_FRAMEWORKS,
                website="https://cakephp.org",
                priority=75,
            )
            .required_rule(req_regex("cakephp", r"cakephp|caKE\[|x-powered-by.*cakephp"))
            .optional(
                header=(ind("header", "cakephp", weight=85),),
            ),
            b(
                id="express",
                name="Express",
                category=Cat.BACKEND_FRAMEWORKS,
                website="https://expressjs.com",
                priority=80,
            )
            .required_rule(req_regex("express", r"express|x-powered-by.*express"))
            .optional(
                header=(ind("header", "express", weight=85),),
                package=(ind("pkg", "express", weight=80),),
            ),
            b(
                id="nestjs",
                name="NestJS",
                category=Cat.BACKEND_FRAMEWORKS,
                website="https://nestjs.com",
                priority=85,
            )
            .required_rule(req_regex("nestjs", r"@nestjs/|nestjs"))
            .optional(
                package=(ind("pkg", "@nestjs/core", weight=95),),
            ),
            b(
                id="fastify",
                name="Fastify",
                category=Cat.BACKEND_FRAMEWORKS,
                website="https://fastify.dev",
                priority=80,
            )
            .required_rule(req_regex("fastify", r"fastify|x-powered-by.*fastify"))
            .optional(
                package=(ind("pkg", "fastify", weight=90),),
            ),
            b(
                id="aspnet",
                name="ASP.NET",
                category=Cat.BACKEND_FRAMEWORKS,
                vendor="Microsoft",
                website="https://dotnet.microsoft.com",
                priority=85,
            )
            .alias("asp.net")
            .required_rule(req_regex("aspnet", r"x-aspnet|asp\.net|__viewstate"))
            .optional(
                header=(ind("header", "asp.net", weight=90),),
                html=(ind("viewstate", "__viewstate", weight=85),),
            ),
            b(
                id="blazor",
                name="Blazor",
                category=Cat.FRONTEND_FRAMEWORKS,
                vendor="Microsoft",
                priority=80,
            )
            .depends("aspnet")
            .required_rule(req_regex("blazor", r"blazor|_framework/blazor"))
            .optional(
                content=(ind("fw", "blazor.webassembly.js", weight=90),),
            ),
            b(
                id="spring-boot",
                name="Spring Boot",
                category=Cat.BACKEND_FRAMEWORKS,
                vendor="VMware",
                website="https://spring.io",
                priority=85,
            )
            .alias("spring")
            .required_rule(
                req_regex("spring-boot", r"spring boot|springframework|whitelabel error page")
            )
            .optional(
                header=(ind("header", "spring", weight=85),),
                content=(ind("error", "whitelabel error page", weight=80),),
            ),
            b(
                id="django",
                name="Django",
                category=Cat.BACKEND_FRAMEWORKS,
                website="https://djangoproject.com",
                priority=85,
            )
            .required_rule(req_regex("django", r"csrftoken|django|x-frame-options"))
            .optional(
                header=(
                    ind("csrf", "csrftoken", weight=85),
                    ind("header", "django", weight=90),
                )
            ),
            b(
                id="flask",
                name="Flask",
                category=Cat.BACKEND_FRAMEWORKS,
                website="https://flask.palletsprojects.com",
                priority=80,
            )
            .required_rule(req_regex("flask", r"werkzeug|flask|set-cookie.*session"))
            .optional(
                header=(ind("header", "werkzeug", weight=85),),
            ),
            b(
                id="fastapi",
                name="FastAPI",
                category=Cat.BACKEND_FRAMEWORKS,
                website="https://fastapi.tiangolo.com",
                priority=80,
            )
            .required_rule(req_regex("fastapi", r"fastapi|x-fastapi|openapi.*fastapi"))
            .optional(
                content=(ind("openapi", "fastapi", weight=85),),
            ),
            b(
                id="rails",
                name="Ruby on Rails",
                category=Cat.BACKEND_FRAMEWORKS,
                website="https://rubyonrails.org",
                priority=85,
            )
            .alias("ruby-on-rails")
            .required_rule(
                req_regex("rails", r"rails|ruby on rails|x-runtime.*rails|csrf-token.*rails")
            )
            .optional(
                header=(ind("runtime", "x-runtime", weight=85),),
                metadata=(ind("meta", "csrf-token", weight=80),),
            ),
            b(
                id="phoenix",
                name="Phoenix",
                category=Cat.BACKEND_FRAMEWORKS,
                website="https://phoenixframework.org",
                priority=80,
            )
            .required_rule(req_regex("phoenix", r"phoenix|/_phoenix/|x-request-id.*phoenix"))
            .optional(
                content=(ind("channel", "/phoenix/", weight=85),),
            ),
            b(
                id="go-fiber",
                name="Go Fiber",
                category=Cat.BACKEND_FRAMEWORKS,
                website="https://gofiber.io",
                priority=75,
            )
            .required_rule(req_regex("go-fiber", r"gofiber|fiber\.v[0-9]"))
            .optional(
                header=(ind("header", "fiber", weight=80),),
            ),
            b(
                id="go-gin",
                name="Go Gin",
                category=Cat.BACKEND_FRAMEWORKS,
                website="https://gin-gonic.com",
                priority=75,
            )
            .required_rule(req_regex("go-gin", r"gin-gonic|gin\.contex"))
            .optional(
                content=(ind("gin", "gin-gonic", weight=80),),
            ),
        ],
    )

    # Web Servers & Infrastructure
    items.extend(
        [
            b(
                id="nginx",
                name="Nginx",
                category=Cat.WEB_SERVERS,
                website="https://nginx.org",
                priority=80,
            )
            .required_rule(req_regex("nginx", r"nginx|x-powered-by.*nginx"))
            .optional(
                header=(ind("server", "nginx", weight=90),),
            ),
            b(
                id="apache",
                name="Apache",
                category=Cat.WEB_SERVERS,
                website="https://httpd.apache.org",
                priority=80,
            )
            .required_rule(req_regex("apache", r"apache|x-powered-by.*apache"))
            .optional(
                header=(ind("server", "apache", weight=90),),
            ),
            b(
                id="caddy",
                name="Caddy",
                category=Cat.WEB_SERVERS,
                website="https://caddyserver.com",
                priority=75,
            )
            .required_rule(req_regex("caddy", r"caddy|via.*caddy"))
            .optional(
                header=(ind("server", "caddy", weight=90),),
            ),
            b(
                id="litespeed",
                name="LiteSpeed",
                category=Cat.WEB_SERVERS,
                website="https://litespeedtech.com",
                priority=75,
            )
            .required_rule(req_regex("litespeed", r"litespeed|x-powered-by.*litespeed"))
            .optional(
                header=(ind("server", "litespeed", weight=90),),
            ),
            b(
                id="cloudflare",
                name="Cloudflare",
                category=Cat.CDNS,
                website="https://cloudflare.com",
                priority=90,
            )
            .required_rule(req_regex("cloudflare", r"cloudflare|cf-ray|__cf_bm"))
            .optional(
                header=(ind("ray", "cf-ray", weight=95),),
                http=(ind("cookie", "__cf_bm", weight=90),),
            ),
            b(id="cloudfront", name="CloudFront", category=Cat.CDNS, vendor="AWS", priority=85)
            .required_rule(req_regex("cloudfront", r"cloudfront|x-amz-cf-"))
            .optional(
                header=(ind("cf", "x-amz-cf-id", weight=95),),
            ),
            b(
                id="fastly",
                name="Fastly",
                category=Cat.CDNS,
                website="https://fastly.com",
                priority=85,
            )
            .required_rule(req_regex("fastly", r"fastly|x-fastly-request-id"))
            .optional(
                header=(ind("fastly", "x-fastly-request-id", weight=95),),
            ),
            b(
                id="akamai",
                name="Akamai",
                category=Cat.CDNS,
                website="https://akamai.com",
                priority=85,
            )
            .required_rule(req_regex("akamai", r"akamai|x-akamai|akamai-"))
            .optional(
                header=(ind("akamai", "x-akamai", weight=90),),
            ),
        ],
    )

    # Hosting Platforms
    items.extend(
        [
            b(
                id="vercel",
                name="Vercel",
                category=Cat.HOSTING_PLATFORMS,
                website="https://vercel.com",
                priority=90,
            )
            .required_rule(req_regex("vercel", r"vercel|x-vercel|/_vercel/"))
            .optional(
                header=(ind("header", "x-vercel", weight=95),),
            ),
            b(
                id="netlify",
                name="Netlify",
                category=Cat.HOSTING_PLATFORMS,
                website="https://netlify.com",
                priority=85,
            )
            .required_rule(req_regex("netlify", r"netlify|x-nf-request-id"))
            .optional(
                header=(ind("header", "x-nf-request-id", weight=95),),
            ),
            b(
                id="render",
                name="Render",
                category=Cat.HOSTING_PLATFORMS,
                website="https://render.com",
                priority=80,
            )
            .required_rule(req_regex("render", r"render\.com|x-render-origin"))
            .optional(
                header=(ind("header", "x-render", weight=90),),
            ),
            b(
                id="railway",
                name="Railway",
                category=Cat.HOSTING_PLATFORMS,
                website="https://railway.app",
                priority=80,
            )
            .required_rule(req_regex("railway", r"railway\.app|railway"))
            .optional(
                header=(ind("header", "railway", weight=85),),
            ),
            b(
                id="flyio",
                name="Fly.io",
                category=Cat.HOSTING_PLATFORMS,
                website="https://fly.io",
                priority=80,
            )
            .alias("fly.io")
            .required_rule(req_regex("flyio", r"fly\.io|x-fly-request-id"))
            .optional(
                header=(ind("header", "fly.io", weight=85),),
            ),
            b(
                id="firebase",
                name="Firebase",
                category=Cat.HOSTING_PLATFORMS,
                vendor="Google",
                website="https://firebase.google.com",
                priority=85,
            )
            .required_rule(req_regex("firebase", r"firebase|firebaseapp\.com|firebaseio\.com"))
            .optional(
                content=(ind("host", "firebaseapp.com", weight=90),),
            ),
            b(
                id="supabase",
                name="Supabase",
                category=Cat.HOSTING_PLATFORMS,
                website="https://supabase.com",
                priority=85,
            )
            .required_rule(req_regex("supabase", r"supabase|supabase\.co"))
            .optional(
                content=(ind("host", "supabase.co", weight=90),),
                package=(ind("pkg", "@supabase/supabase-js", weight=90),),
            ),
        ],
    )

    # Authentication & Payment
    items.extend(
        [
            b(
                id="auth0",
                name="Auth0",
                category=Cat.AUTHENTICATION,
                website="https://auth0.com",
                priority=85,
            )
            .required_rule(req_regex("auth0", r"auth0\.com|auth0-js|auth0-spa-js"))
            .optional(
                package=(ind("pkg", "auth0", weight=90),),
                content=(ind("cdn", "auth0.com", weight=85),),
            ),
            b(
                id="clerk",
                name="Clerk",
                category=Cat.AUTHENTICATION,
                website="https://clerk.com",
                priority=85,
            )
            .required_rule(req_regex("clerk", r"clerk\.com|@clerk/|clerk\.browser"))
            .optional(
                package=(ind("pkg", "@clerk/clerk-js", weight=95),),
            ),
            b(
                id="stripe",
                name="Stripe",
                category=Cat.PAYMENT,
                website="https://stripe.com",
                priority=90,
            )
            .required_rule(req_regex("stripe", r"stripe\.com|js\.stripe\.com|stripe-js"))
            .optional(
                content=(ind("js", "js.stripe.com", weight=95),),
                runtime=(ind("stripe", "stripe", weight=85),),
            ),
            b(
                id="paypal",
                name="PayPal",
                category=Cat.PAYMENT,
                website="https://paypal.com",
                priority=85,
            )
            .required_rule(req_regex("paypal", r"paypal\.com|paypalobjects|paypal-sdk"))
            .optional(
                content=(ind("sdk", "paypal.com/sdk", weight=90),),
            ),
        ],
    )

    # Analytics & Tag Managers
    items.extend(
        [
            b(
                id="google-analytics",
                name="Google Analytics",
                category=Cat.ANALYTICS,
                vendor="Google",
                priority=90,
            )
            .alias("ga", "gtag")
            .required_rule(
                req_regex(
                    "google-analytics",
                    r"google-analytics|gtag|googletagmanager|ga\.js|analytics\.js",
                )
            )
            .optional(
                runtime=(ind("gtag", "gtag(", weight=90),),
                content=(ind("ga", "google-analytics.com", weight=95),),
            ),
            b(
                id="google-tag-manager",
                name="Google Tag Manager",
                category=Cat.TAG_MANAGERS,
                vendor="Google",
                priority=90,
            )
            .alias("gtm")
            .required_rule(
                req_regex(
                    "google-tag-manager", r"googletagmanager\.com/gtm|gtm\.js|google_tag_manager"
                )
            )
            .optional(
                content=(ind("gtm", "googletagmanager.com/gtm", weight=95),),
            ),
            b(
                id="hotjar",
                name="Hotjar",
                category=Cat.ANALYTICS,
                website="https://hotjar.com",
                priority=80,
            )
            .required_rule(req_regex("hotjar", r"hotjar|static\.hotjar\.com"))
            .optional(
                content=(ind("script", "hotjar.com", weight=90),),
            ),
            b(
                id="matomo",
                name="Matomo",
                category=Cat.ANALYTICS,
                website="https://matomo.org",
                priority=80,
            )
            .required_rule(req_regex("matomo", r"matomo|piwik"))
            .optional(
                content=(ind("piwik", "matomo.js", weight=90),),
            ),
            b(
                id="plausible",
                name="Plausible",
                category=Cat.ANALYTICS,
                website="https://plausible.io",
                priority=80,
            )
            .required_rule(req_regex("plausible", r"plausible\.io|plausible\.js"))
            .optional(
                content=(ind("script", "plausible.io", weight=90),),
            ),
        ],
    )

    # Monitoring & Search
    items.extend(
        [
            b(
                id="sentry",
                name="Sentry",
                category=Cat.MONITORING,
                website="https://sentry.io",
                priority=85,
            )
            .required_rule(req_regex("sentry", r"sentry\.io|@sentry/|sentry-browser"))
            .optional(
                package=(ind("pkg", "@sentry/browser", weight=95),),
                content=(ind("cdn", "sentry.io", weight=90),),
            ),
            b(
                id="elastic",
                name="Elastic",
                category=Cat.SEARCH_ENGINES,
                vendor="Elastic",
                website="https://elastic.co",
                priority=80,
            )
            .alias("elasticsearch")
            .required_rule(req_regex("elastic", r"elasticsearch|elastic\.co|kibana"))
            .optional(
                content=(ind("es", "elasticsearch", weight=85),),
            ),
            b(
                id="algolia",
                name="Algolia",
                category=Cat.SEARCH_ENGINES,
                website="https://algolia.com",
                priority=85,
            )
            .required_rule(req_regex("algolia", r"algolia|algoliasearch|algolianet"))
            .optional(
                package=(ind("pkg", "algoliasearch", weight=95),),
                runtime=(ind("search", "algolia", weight=85),),
            ),
            b(
                id="meilisearch",
                name="Meilisearch",
                category=Cat.SEARCH_ENGINES,
                website="https://meilisearch.com",
                priority=80,
            )
            .required_rule(req_regex("meilisearch", r"meilisearch|meilisearch\.js"))
            .optional(
                package=(ind("pkg", "meilisearch", weight=90),),
            ),
            b(id="opensearch", name="OpenSearch", category=Cat.SEARCH_ENGINES, priority=80)
            .required_rule(req_regex("opensearch", r"opensearch|opensearch\.org"))
            .optional(
                content=(ind("os", "opensearch", weight=85),),
            ),
        ],
    )

    # Databases & Messaging
    items.extend(
        [
            b(
                id="redis",
                name="Redis",
                category=Cat.DATABASES,
                website="https://redis.io",
                priority=75,
            )
            .required_rule(req_regex("redis", r"redis|x-redis"))
            .optional(
                header=(ind("header", "redis", weight=80),),
                metadata=(ind("meta", "redis", weight=75),),
            ),
            b(id="rabbitmq", name="RabbitMQ", category=Cat.DATABASES, priority=75)
            .required_rule(req_regex("rabbitmq", r"rabbitmq|amqp"))
            .optional(
                content=(ind("amqp", "rabbitmq", weight=80),),
            ),
            b(id="kafka", name="Apache Kafka", category=Cat.DATABASES, priority=75)
            .required_rule(req_regex("kafka", r"kafka|confluent"))
            .optional(
                content=(ind("kafka", "kafka", weight=80),),
            ),
        ],
    )

    return items

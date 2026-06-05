import { defineConfig } from 'vitepress'

// VitePress config for the Private Verifiable Compute documentation site.
// The site sources its pages from the existing markdown files under `docs/`.
export default defineConfig({
  title: 'Private Verifiable Compute',
  description:
    'Private and verifiable compute environment for context-aware AI processing with sensitive data.',
  lang: 'en-US',
  cleanUrls: true,
  lastUpdated: true,
  ignoreDeadLinks: 'localhostLinks',

  head: [
    ['meta', { name: 'theme-color', content: '#3c8772' }],
    ['meta', { property: 'og:type', content: 'website' }],
    ['meta', { property: 'og:title', content: 'Private Verifiable Compute' }],
    [
      'meta',
      {
        property: 'og:description',
        content:
          'Enabling Private AI Processing with verifiable transparency.',
      },
    ],
  ],

  themeConfig: {
    nav: [
      { text: 'Home', link: '/' },
      { text: 'Getting Started', link: '/build' },
    ],

    sidebar: [
      {
        text: 'Getting Started',
        collapsed: false,
        items: [
          { text: 'Build PVC', link: '/build' },
          { text: 'Try on Minikube', link: '/minikube' },
          { text: 'Deploy on GCP', link: '/gcp' },
          { text: 'Deploy on Confidential Containers', link: '/coco' },
          { text: 'PVC CLI', link: '/pvc-cli' },
          { text: 'Reproducible Builds', link: '/reproducibility' },
          { text: 'pvc-client-js Deployment', link: '/pvc-client-js-deploy' },
        ],
      },
      {
        text: 'Architecture',
        collapsed: false,
        items: [
          { text: 'Anonymous Routing', link: '/anonymous_routing' },
          { text: 'Noise Framework', link: '/noise' },
        ],
      },
    ],

    socialLinks: [
      {
        icon: 'github',
        link: 'https://github.com/tiktok-privacy-innovation/private-verifiable-compute',
      },
    ],

    search: {
      provider: 'local',
    },

    editLink: {
      pattern:
        'https://github.com/tiktok-privacy-innovation/private-verifiable-compute/edit/main/docs/:path',
      text: 'Edit this page on GitHub',
    },

    footer: {
      message:
        'Released under the Apache License 2.0. Private Verifiable Compute is an ongoing research project under active development.',
      copyright: 'Copyright © Private Verifiable Compute contributors',
    },

    outline: {
      level: [2, 3],
      label: 'On this page',
    },
  },
})

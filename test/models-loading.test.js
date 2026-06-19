import { describe, it, expect } from 'vitest'

// Characterization (golden-master) tests for the JSON-Schema "plugin" loader.
//
// These lock the CURRENT behavior of:
//   - models/sections.js  -> exports a fn returning the list of section names
//                            discovered under ./default and ./custom
//   - models/set.js       -> exports optSet(setName, paths) which merges a
//                            section's conf.js with computed template/asset
//                            paths (list/edit/render/static/style/script).
//
// Both modules are plain CommonJS and resolve paths relative to process.cwd().
// vitest runs from the repo root (/Users/hcf/Projects/OpenVG), so the relative
// fs.existsSync / require('../'+path+...) calls resolve against the repo root.
//
// CommonJS modules import as a default in vitest.
import optSet from '../models/set.js'
import getSections from '../models/sections.js'

// At the time of writing there is NO ./custom directory; only ./default exists
// with sections: cve5, cvss4, home, nvd. (There is intentionally no plain "cve"
// section — only "cve5".) These tests are written to that reality. The
// custom-override tests below describe/skip when ./custom is absent.

describe('sections.js — section discovery', () => {
  it('is exported as a function (default import of a CommonJS module)', () => {
    expect(typeof getSections).toBe('function')
  })

  it('returns an array of section names', () => {
    const sections = getSections()
    expect(Array.isArray(sections)).toBe(true)
  })

  it('returns exactly the section directories present under ./default today', () => {
    const sections = getSections()
    // Order follows fs.readdirSync of ./default, then ./custom (none today).
    expect(sections).toEqual(['cve5', 'cvss4', 'home', 'nvd'])
  })

  it('includes each known default section', () => {
    const sections = getSections()
    expect(sections).toContain('cve5')
    expect(sections).toContain('cvss4')
    expect(sections).toContain('home')
    expect(sections).toContain('nvd')
  })

  it('does NOT include a plain "cve" section (only "cve5" exists)', () => {
    const sections = getSections()
    expect(sections).not.toContain('cve')
  })

  it('omits dotfiles / hidden entries (none leak through)', () => {
    const sections = getSections()
    expect(sections.some((n) => n.startsWith('.'))).toBe(false)
  })

  it('returns unique names (object-keys dedupe across default+custom)', () => {
    const sections = getSections()
    expect(new Set(sections).size).toBe(sections.length)
  })

  it('is stable across repeated calls', () => {
    expect(getSections()).toEqual(getSections())
  })

  it('snapshot of the full section list', () => {
    expect(getSections()).toMatchSnapshot()
  })
})

describe('set.js — export shape', () => {
  it('is exported as a function (default import of a CommonJS module)', () => {
    expect(typeof optSet).toBe('function')
  })
})

describe('optSet — default skeleton for unknown / missing sections', () => {
  it('returns only the {list, edit, render} skeleton for a nonexistent section', () => {
    const r = optSet('doesnotexist', ['default'])
    expect(r).toEqual({ list: 'list', edit: 'edit', render: 'render' })
  })

  it('returns only the skeleton when paths is an empty array (nothing scanned)', () => {
    const r = optSet('cve5', [])
    expect(r).toEqual({ list: 'list', edit: 'edit', render: 'render' })
  })

  it('default template values are the literal strings list/edit/render', () => {
    const r = optSet('doesnotexist', ['default'])
    expect(r.list).toBe('list')
    expect(r.edit).toBe('edit')
    expect(r.render).toBe('render')
  })

  it('skeleton object has no extra keys', () => {
    const r = optSet('doesnotexist', ['default'])
    expect(Object.keys(r).sort()).toEqual(['edit', 'list', 'render'])
  })
})

describe('optSet — default paths argument (paths omitted -> [default, custom])', () => {
  // When paths is falsy, set.js uses ['default','custom']. There is no ./custom
  // dir today, so the result matches passing ['default'] alone.
  it('produces the same result for nvd whether paths omitted or ["default"]', () => {
    const omitted = optSet('nvd')
    const explicit = optSet('nvd', ['default'])
    expect(Object.keys(omitted).sort()).toEqual(Object.keys(explicit).sort())
    expect(omitted.conf).toEqual(explicit.conf)
    expect(omitted.facet).toEqual(explicit.facet)
  })

  it('produces the same template paths for cve5 whether paths omitted or ["default"]', () => {
    const omitted = optSet('cve5')
    const explicit = optSet('cve5', ['default'])
    expect(omitted.list).toBe(explicit.list)
    expect(omitted.edit).toBe(explicit.edit)
    expect(omitted.render).toBe(explicit.render)
    expect(omitted.static).toBe(explicit.static)
  })
})

describe('optSet("cve5", ["default"]) — full plugin shape', () => {
  const r = optSet('cve5', ['default'])

  it('has the expected top-level keys', () => {
    expect(Object.keys(r).sort()).toEqual([
      'conf',
      'edit',
      'facet',
      'icons',
      'list',
      'render',
      'router',
      'schema',
      'script',
      'static',
      'style',
      'validators',
    ])
  })

  it('resolves edit and render templates to ../default/cve5/* paths', () => {
    expect(r.edit).toBe('../default/cve5/edit')
    expect(r.render).toBe('../default/cve5/render')
  })

  it('leaves list as the default string because cve5 has cvelist.pug, not list.pug', () => {
    // Only list/edit/render.pug are looked for; cve5 ships cvelist.pug + edit.pug
    // + render.pug, so list stays default while edit/render resolve.
    expect(r.list).toBe('list')
  })

  it('points static at the section static directory', () => {
    expect(r.static).toBe('default/cve5/static')
  })

  it('loads style as a string from style.css', () => {
    expect(typeof r.style).toBe('string')
    expect(r.style.length).toBe(4487)
  })

  it('loads script as a string from script.js', () => {
    expect(typeof r.script).toBe('string')
    expect(r.script.length).toBe(45785)
  })

  it('exposes schema as an object (draft-07 CVE record schema)', () => {
    expect(typeof r.schema).toBe('object')
    expect(r.schema).not.toBeNull()
    expect(r.schema['$schema']).toBe('http://json-schema.org/draft-07/schema#')
    expect(r.schema.title).toBe('CVE JSON record format')
    expect(r.schema['$id']).toBe('https://cve.org/cve/record/v5_00/')
  })

  it('exposes conf with the expected metadata', () => {
    expect(r.conf.title).toBe('CVE: Common Vulnerabilities and Exposures')
    expect(r.conf.name).toBe('CVE 5.0')
    expect(r.conf.uri).toBe('/cve5/')
    expect(r.conf.class).toBe('vgi-alert')
    expect(r.conf.order).toBe(0.12)
    expect(Object.keys(r.conf)).toEqual([
      'title',
      'name',
      'uri',
      'class',
      'order',
      'shortcuts',
    ])
  })

  it('conf.shortcuts carries a My CVEs entry whose href is a function', () => {
    expect(Array.isArray(r.conf.shortcuts)).toBe(true)
    expect(r.conf.shortcuts).toHaveLength(1)
    expect(r.conf.shortcuts[0].label).toBe('My CVEs')
    expect(r.conf.shortcuts[0].class).toBe('vgi-folder')
    expect(typeof r.conf.shortcuts[0].href).toBe('function')
  })

  it('exposes router as a function', () => {
    expect(typeof r.router).toBe('function')
  })

  it('exposes icons as an object map', () => {
    expect(typeof r.icons).toBe('object')
    expect(Array.isArray(r.icons)).toBe(false)
    expect(r.icons).toHaveProperty('ID')
    expect(r.icons).toHaveProperty('References')
  })

  it('exposes validators as an array holding a single validator function', () => {
    expect(Array.isArray(r.validators)).toBe(true)
    expect(r.validators).toHaveLength(1)
    expect(typeof r.validators[0]).toBe('function')
  })

  describe('facet structure', () => {
    it('has the expected facet keys', () => {
      expect(Object.keys(r.facet)).toEqual([
        'ID',
        'title',
        'state',
        'type',
        'cveState',
        'cvss',
        'severity',
        'discovery',
        'defect',
        'date',
        'updated',
        'product',
        'ym',
        'owner',
      ])
    })

    it('facet.ID describes the CVE id path/regex', () => {
      expect(r.facet.ID).toEqual({
        path: 'body.cveMetadata.cveId',
        regex: 'CVE-[a-zA-Z0-9._-]+',
        showDistinct: true,
      })
    })

    it('facet.title cross-references the ID', () => {
      expect(r.facet.title).toEqual({
        path: 'body.containers.cna.title',
        href: '/cve5/',
        xref: { href: 'ID' },
      })
    })

    it('facet.cvss points at the CVSS v4.0 base score', () => {
      expect(r.facet.cvss).toEqual({
        path: 'body.containers.cna.metrics.cvssV4_0.baseScore',
      })
    })

    it('facet.state enumerates the workflow states', () => {
      expect(r.facet.state.enum).toEqual([
        'new',
        'open',
        'draft',
        'review',
        'waiting',
        'pending',
        'closed',
      ])
      expect(r.facet.state.tabs).toBe(true)
      expect(r.facet.state.bulk).toBe(true)
    })

    it('snapshot of the full facet block', () => {
      expect(r.facet).toMatchSnapshot()
    })
  })

  it('snapshot of conf', () => {
    expect(r.conf).toMatchSnapshot()
  })

  it('snapshot of icons map', () => {
    expect(r.icons).toMatchSnapshot()
  })

  it('snapshot of resolved template/static/path facts', () => {
    expect({
      list: r.list,
      edit: r.edit,
      render: r.render,
      static: r.static,
      styleLen: r.style.length,
      scriptLen: r.script.length,
      schemaTitle: r.schema.title,
      validators: r.validators,
    }).toMatchSnapshot()
  })
})

describe('optSet("cve5") — assets sourced verbatim from files', () => {
  // Lock that style/script/schema are byte-for-byte what the source files hold.
  it('style equals the contents of default/cve5/style.css', () => {
    const fs = require('fs')
    const css = fs.readFileSync('./default/cve5/style.css', 'utf8')
    const r = optSet('cve5', ['default'])
    expect(r.style).toBe(css)
  })

  it('script equals the contents of default/cve5/script.js', () => {
    const fs = require('fs')
    const js = fs.readFileSync('./default/cve5/script.js', { encoding: 'utf8' })
    const r = optSet('cve5', ['default'])
    expect(r.script).toBe(js)
  })

  it('schema title/$id equal the parsed cve5.schema.json', () => {
    const fs = require('fs')
    const raw = JSON.parse(fs.readFileSync('./default/cve5/cve5.schema.json', 'utf8'))
    const r = optSet('cve5', ['default'])
    expect(r.schema.title).toBe(raw.title)
    expect(r.schema['$id']).toBe(raw['$id'])
  })
})

describe('optSet("cvss4", ["default"]) — calculator section', () => {
  const r = optSet('cvss4', ['default'])

  it('has the expected top-level keys (no script)', () => {
    expect(Object.keys(r).sort()).toEqual([
      'conf',
      'edit',
      'facet',
      'list',
      'render',
      'router',
      'schema',
      'static',
      'style',
      'validators',
    ])
  })

  it('resolves only edit (only edit.pug ships); list and render stay default', () => {
    expect(r.edit).toBe('../default/cvss4/edit')
    expect(r.list).toBe('list')
    expect(r.render).toBe('render')
  })

  it('has no script (cvss4 ships no script.js)', () => {
    expect('script' in r).toBe(false)
    expect(r.script).toBeUndefined()
  })

  it('points static at default/cvss4/static', () => {
    expect(r.static).toBe('default/cvss4/static')
  })

  it('loads style from style.css', () => {
    expect(typeof r.style).toBe('string')
    expect(r.style.length).toBe(2784)
  })

  it('conf carries favicon / ogImage metadata', () => {
    expect(r.conf.name).toBe('CVSS 4.0')
    expect(r.conf.uri).toBe('/cvss4/')
    expect(r.conf.class).toBe('vgi-cvss-logo')
    expect(r.conf.favicon).toBe(
      'https://raw.githubusercontent.com/Vulnogram/vg-icons/refs/heads/main/src/cvss.svg'
    )
    expect(r.conf.ogImage).toBe('https://vulnogram.org/screenshots/cvssog.png')
    expect(r.conf.order).toBe(0.12)
  })

  it('facet.ID matches the CVSS vector string path/regex', () => {
    expect(r.facet.ID).toEqual({
      path: 'body.vectorString',
      regex: 'CVSS[a-zA-Z0-9._-]+',
      showDistinct: true,
    })
  })

  it('exposes router as a function and validators present', () => {
    expect(typeof r.router).toBe('function')
    expect('validators' in r).toBe(true)
  })

  it('schema is an object', () => {
    expect(typeof r.schema).toBe('object')
    expect(r.schema).not.toBeNull()
  })

  it('snapshot of conf', () => {
    expect(r.conf).toMatchSnapshot()
  })

  it('snapshot of facet', () => {
    expect(r.facet).toMatchSnapshot()
  })
})

describe('optSet("home", ["default"]) — dashboard section', () => {
  const r = optSet('home', ['default'])

  it('has the expected top-level keys (no router/icons/validators)', () => {
    expect(Object.keys(r).sort()).toEqual([
      'conf',
      'edit',
      'facet',
      'list',
      'render',
      'schema',
      'script',
      'static',
      'style',
    ])
  })

  it('resolves all three templates (list.pug, edit.pug, render.pug all ship)', () => {
    expect(r.list).toBe('../default/home/list')
    expect(r.edit).toBe('../default/home/edit')
    expect(r.render).toBe('../default/home/render')
  })

  it('points static at default/home/static', () => {
    expect(r.static).toBe('default/home/static')
  })

  it('loads style and script as strings', () => {
    expect(typeof r.style).toBe('string')
    expect(r.style.length).toBe(1809)
    expect(typeof r.script).toBe('string')
    expect(r.script.length).toBe(284)
  })

  it('conf carries dashboard metadata with a negative order', () => {
    expect(r.conf).toEqual({
      title: 'Dashboard',
      name: 'Vulndesk',
      class: 'vgi-logo',
      order: -10,
      uri: '/home/',
    })
  })

  it('has NO router/icons/validators (home conf.js does not export them)', () => {
    expect('router' in r).toBe(false)
    expect('icons' in r).toBe(false)
    expect('validators' in r).toBe(false)
  })

  it('facet.ID describes the PLOT id', () => {
    expect(r.facet.ID).toEqual({
      path: 'body.ID',
      regex: 'PLOT-[A-Za-z0-9-_]+',
      chart: false,
      href: '/home/',
      hrefSuffix: '#chart',
    })
  })

  it('snapshot of facet', () => {
    expect(r.facet).toMatchSnapshot()
  })
})

describe('optSet("nvd", ["default"]) — minimal read-only section', () => {
  const r = optSet('nvd', ['default'])

  it('has only conf, edit, facet, list, render, style (no schema/static/script)', () => {
    expect(Object.keys(r).sort()).toEqual([
      'conf',
      'edit',
      'facet',
      'list',
      'render',
      'style',
    ])
  })

  it('all three templates stay at their default strings (no pug files ship)', () => {
    expect(r.list).toBe('list')
    expect(r.edit).toBe('edit')
    expect(r.render).toBe('render')
  })

  it('has no static directory', () => {
    expect('static' in r).toBe(false)
    expect(r.static).toBeUndefined()
  })

  it('has no schema and no script', () => {
    expect('schema' in r).toBe(false)
    expect('script' in r).toBe(false)
  })

  it('loads style from style.css', () => {
    expect(typeof r.style).toBe('string')
    expect(r.style.length).toBe(989)
  })

  it('conf marks the section read-only', () => {
    expect(r.conf.readonly).toBe(true)
    expect(r.conf.name).toBe('NVD')
    expect(r.conf.title).toBe('National Vulnerability Database')
    expect(r.conf.class).toBe('vgi-data')
  })

  it('facet.ID describes the legacy CVE_data_meta path', () => {
    expect(r.facet.ID).toEqual({
      path: 'cve.CVE_data_meta.ID',
      regex: 'CVE-[0-9]{4}-[0-9]{4,10}',
      class: 'nobr',
    })
  })

  it('snapshot of conf', () => {
    expect(r.conf).toMatchSnapshot()
  })

  it('snapshot of facet', () => {
    expect(r.facet).toMatchSnapshot()
  })
})

describe('optSet — cross-section invariants', () => {
  const names = ['cve5', 'cvss4', 'home', 'nvd']

  it('every real section returns an object with a conf and a facet that has an ID', () => {
    for (const name of names) {
      const r = optSet(name, ['default'])
      expect(typeof r).toBe('object')
      expect(typeof r.conf).toBe('object')
      expect(typeof r.facet).toBe('object')
      expect(r.facet).toHaveProperty('ID')
      expect(r.facet.ID).toHaveProperty('path')
    }
  })

  it('every real section always exposes list/edit/render keys', () => {
    for (const name of names) {
      const r = optSet(name, ['default'])
      expect(r).toHaveProperty('list')
      expect(r).toHaveProperty('edit')
      expect(r).toHaveProperty('render')
    }
  })

  it('results are stable (deep-equal) across repeated calls', () => {
    for (const name of names) {
      expect(optSet(name, ['default'])).toEqual(optSet(name, ['default']))
    }
  })

  it('each call returns a fresh top-level object (not a shared reference)', () => {
    expect(optSet('cve5', ['default'])).not.toBe(optSet('cve5', ['default']))
  })

  it('snapshot of the resolved path/asset facts for every section', () => {
    const summary = {}
    for (const name of names) {
      const r = optSet(name, ['default'])
      summary[name] = {
        list: r.list,
        edit: r.edit,
        render: r.render,
        static: r.static ?? null,
        hasSchema: 'schema' in r,
        hasScript: 'script' in r,
        hasStyle: 'style' in r,
        hasRouter: 'router' in r,
        hasIcons: 'icons' in r,
        hasValidators: 'validators' in r,
      }
    }
    expect(summary).toMatchSnapshot()
  })
})

describe('optSet — custom-override behavior', () => {
  const fs = require('fs')
  const hasCustom = fs.existsSync('./custom')

  it('there is no ./custom directory in this checkout (so default wins by default)', () => {
    // Lock the current reality: no custom overrides exist today.
    expect(hasCustom).toBe(false)
  })

  // When ./custom exists, set.js scans default THEN custom; conf objects are
  // deep-extended (custom merged over default) and template/static/style/script
  // get overwritten by the later (custom) path. With no ./custom dir, this is a
  // describe.skip placeholder documenting the intended override contract.
  describe.skip('custom overrides default (requires a ./custom directory)', () => {
    it('placeholder — exercise once a ./custom/<section> exists', () => {})
  })
})

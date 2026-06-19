const { test, expect } = require('@playwright/test')

// Characterization E2E for the standalone CVE editor — locks the real editor UX
// (the parity spec the React rewrite must match). Uses the json-editor field
// `name` attributes and the tab radio/label ids, which are stable.

const CVE_ID_FIELD = 'input[name="root[cveMetadata][cveId]"]'
const tab = (id) => `label[for="${id}"]`

test.beforeEach(async ({ page }) => {
  await page.goto('/index.html')
  await page.locator(CVE_ID_FIELD).waitFor({ state: 'visible' })
})

test('loads as the Vulndesk CVE Editor', async ({ page }) => {
  // Note: the static <title> is "Vulndesk CVE Editor", but editor.js overwrites
  // document.title to "Vulndesk" (or the CVE id) at runtime — lock the runtime value.
  await expect(page).toHaveTitle(/^Vulndesk/)
  await expect(page.getByText('Vulndesk', { exact: true }).first()).toBeVisible()
})

test('shows the primary chrome: load box and all four tabs', async ({ page }) => {
  await expect(page.locator('#cveEditable')).toBeVisible() // "Load CVE for editing"
  for (const id of ['editorTab', 'sourceTab', 'advisoryTab', 'cvePortalTab']) {
    await expect(page.locator(tab(id))).toBeVisible()
  }
  for (const label of ['NEW', 'Open', 'Download']) {
    await expect(page.getByText(label).first()).toBeVisible()
  }
})

test('Source tab emits a well-formed CVE5 record skeleton', async ({ page }) => {
  await page.locator(tab('sourceTab')).click()
  const out = page.locator('#output')
  await expect(out).toContainText('"dataType": "CVE_RECORD"')
  await expect(out).toContainText('"dataVersion": "5.1"')
  await expect(out).toContainText('"containers"')
  // The tool stamps itself as the generator — must survive the rewrite.
  await expect(out).toContainText('Vulndesk 0.6.0')
})

test('default record carries the CVSS 4.0 calculator output', async ({ page }) => {
  await page.locator(tab('sourceTab')).click()
  const out = page.locator('#output')
  await expect(out).toContainText('"cvssV4_0"')
  await expect(out).toContainText('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H')
  await expect(out).toContainText('"baseScore": 10')
  await expect(out).toContainText('"baseSeverity": "CRITICAL"')
})

test('editing the CVE ID propagates into the Source JSON', async ({ page }) => {
  const field = page.locator(CVE_ID_FIELD)
  await field.fill('CVE-2024-12345')
  await field.blur()
  await page.locator(tab('sourceTab')).click()
  await expect(page.locator('#output')).toContainText('"cveId": "CVE-2024-12345"')
})

test('CVE Portal tab shows the CVE Services portal', async ({ page }) => {
  await page.locator(tab('cvePortalTab')).click()
  await expect(page.getByText(/CVE Services Portal/i).first()).toBeVisible()
})

test('all tabs switch without throwing', async ({ page }) => {
  const errors = []
  page.on('pageerror', (e) => errors.push(e.message))
  for (const id of ['advisoryTab', 'cvePortalTab', 'sourceTab', 'editorTab']) {
    await page.locator(tab(id)).click()
  }
  expect(errors).toEqual([])
})

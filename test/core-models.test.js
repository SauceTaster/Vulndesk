import { describe, it, expect } from 'vitest'
import { DocumentEnvelopeSchema, CommentSchema, FileMetaSchema } from '@vulndesk/core'

describe('@vulndesk/core Zod domain models', () => {
  it('DocumentEnvelopeSchema defaults comments/files to [] and preserves unknown keys', () => {
    const out = DocumentEnvelopeSchema.parse({
      author: 'alice',
      body: { dataType: 'CVE_RECORD' },
      x_extra: 1,
    })
    expect(out.comments).toEqual([])
    expect(out.files).toEqual([])
    expect(out.body).toEqual({ dataType: 'CVE_RECORD' })
    expect(out.x_extra).toBe(1) // looseObject keeps Mongo's strict:false extras
  })

  it('CommentSchema requires author/slug/hypertext', () => {
    expect(() => CommentSchema.parse({ author: 'a', slug: 's', hypertext: '<b>hi</b>' })).not.toThrow()
    expect(CommentSchema.safeParse({ author: 'a' }).success).toBe(false)
  })

  it('FileMetaSchema requires a name and coerces dates', () => {
    const f = FileMetaSchema.parse({ name: 'x.pdf', updatedAt: '2026-01-01T00:00:00Z', size: 10 })
    expect(f.name).toBe('x.pdf')
    expect(f.updatedAt instanceof Date).toBe(true)
    expect(FileMetaSchema.safeParse({}).success).toBe(false)
  })

  it('DocumentEnvelopeSchema validates nested comments/files', () => {
    const out = DocumentEnvelopeSchema.parse({
      body: {},
      comments: [{ author: 'a', slug: 's', hypertext: 'hi' }],
      files: [{ name: 'f.txt' }],
    })
    expect(out.comments).toHaveLength(1)
    expect(out.files[0].name).toBe('f.txt')
    const bad = DocumentEnvelopeSchema.safeParse({ body: {}, comments: [{ author: 'a' }] })
    expect(bad.success).toBe(false)
  })
})

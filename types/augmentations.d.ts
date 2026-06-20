// Module/global augmentations for the legacy server. This file is a *module*
// (note the `export {}`), so the `declare` blocks below MERGE with the real
// types rather than replacing them — which is what augmentation requires.
export {}

declare global {
  namespace Express {
    // Passport types `req.user` as the empty `Express.User`; the legacy app
    // stores the Mongoose user doc there and reads these fields off it.
    interface User {
      _id?: any
      username?: string
      name?: string
      priv?: number
      group?: string
    }
    // querymen middleware decorates the request with a parsed query object.
    interface Request {
      querymen?: any
    }
  }

  // routes/onedoc.ts uses the CommonJS `module` wrapper as an export bag
  // (`module.router = ...`, `module.addModelHistory = ...`). The global
  // `module` is typed `NodeJS.Module`.
  namespace NodeJS {
    interface Module {
      router?: any
      addModelHistory?: (...args: any[]) => any
    }
  }
}

// app.ts / routes/users.ts stash the post-login redirect target on the session.
declare module 'express-session' {
  interface SessionData {
    returnTo?: string
  }
}

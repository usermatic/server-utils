This module is intended for backends of applications that use
[Usermatic](https://usermatic.io/).

## verifyJwt(token: string, key: string): string | object

verifyJwt verifies a JWT provided by a client who has signed in to your application.
If the JWT signature is authentic, the decoded contents of the JWT are returned.
Otherwise, an Error() is thrown.

Example:

       try {
         const token = verifyJwt(req.headers.authorization, process.env.UM_SECRET)
         res.status(200).send(`You are authenticated as ${ token.id }`)
         return
       } catch (err) {
         res.status(400).send("Ah ah ah, you didn't say the magic word!")
       }

`verifyJwt` is just a wrapper around the `verify` function from
[jsonwebtoken](https://www.npmjs.com/package/jsonwebtoken). However,
it throws an error if you supply an empty key, and restricts the allowed signature
algorithms to those that are used by Usermatic. (Currently, `HS256` only).

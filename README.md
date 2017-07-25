Implementation of  Signing HTTP Messages draft spec for akka HTTP. Client and server libs.

References:
* spec in HTML [Signing HTTP Messages](https://w3c-dvcg.github.io/http-signatures/)
* [IETF tracker of HTTP-signature](https://datatracker.ietf.org/doc/draft-cavage-http-signatures/)   
* [Github repository and issue database for spec](https://github.com/w3c-dvcg/http-signatures)
* [Akka.io](akka.io): the reactive, streaming, actor library 

This code was initially in [rww-play](https://github.com/read-write-web/rww-play/) and was tested with a JavaScript client in [rww-scala-js](https://github.com/read-write-web/rww-scala-js). 

# Usage

The packages are published on a maven repository at http://bblfish.net/work/repo/

Check the tests for library useage. More elaborate tests cases are still in development.

## Java imports

  todo: can't remember how that works  
 

## sbt imports for Scala

```scala
resolvers += "bblfish.net repository" at "http://bblfish.net/work/repo/snapshots/"
libraryDependencies += "run.cosy" %% "akka-http-signature" % "0.2-SNAPSHOT"
```

## Ammonite

For running in the [ammonite.io](http://ammonite.io/) shell script you can
do the following:

```scala
import coursier.core.Authentication, coursier.MavenRepository

interp.repositories() ++= Seq(MavenRepository(
  "http://bblfish.net/work/repo/snapshots/"
  ))

@

import $ivy.`run.cosy::akka-http-signature:0.2-SNAPSHOT`
```

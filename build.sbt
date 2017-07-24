import sbt.Keys.startYear

libraryDependencies ++= Seq(
  "com.typesafe.akka" %% "akka-http" % "10.0.9",
  "com.typesafe.akka" %% "akka-http-testkit" % "10.0.9" % Test
)

// http://www.scalatest.org/install
libraryDependencies += "org.scalactic" %% "scalactic" % "3.0.1"
libraryDependencies += "org.scalatest" %% "scalatest" % "3.0.1" % Test

//http://repo2.maven.org/maven2/org/bouncycastle/bcprov-jdk15on/
libraryDependencies += "org.bouncycastle" % "bcprov-jdk15on" % "1.57" % Test

lazy val pomSettings = Seq(
   pomIncludeRepository := { _ => false},
   pomExtra :=
    <url>https://github.com/read-write-web/akka-http-signature</url>
     <developers>
        <developer>
           <id>bblfish</id>
           <name>Henry Story</name>
           <url>http://bblfish.net/</url>
        </developer>
     </developers>
     <scm>
        <url>git@github.com:read-write-web/akka-http-signature.git</url>
        <connection>scm:git:git@github.com:read-write-web/akka-http-signature.git</connection>
     </scm>
   ,
   licenses +=("Apache", url("http://www.apache.org/licenses/LICENSE-2.0"))
)


//sbt -Dbanana.publish=bblfish.net:/home/hjs/htdocs/work/repo/
//sbt -Dbanana.publish=bintray
lazy val publicationSettings = pomSettings ++ {
  val pubre = """([^:]+):([^:]+)""".r
  Option(System.getProperty("banana.publish")) match {
    case Some("bintray") | None => Seq(
      // removed due to issue https://github.com/typesafehub/dbuild/issues/158
      //      publishTo := {
      //        val nexus = "https://oss.sonatype.org/"
      //        if (isSnapshot.value)
      //          Some("snapshots" at nexus + "content/repositories/snapshots")
      //        else
      //          Some("releases" at nexus + "service/local/staging/deploy/maven2")
      //      },
      //      releasePublishArtifactsAction := PgpKeys.publishSigned.value,
      //      publishArtifact in Test := false
    )
    case Some(pubre(host, path)) =>
      Seq(
        publishTo := Some(
          Resolver.ssh("banana.publish specified server",
            host,
            path + {
              if (isSnapshot.value) "snapshots" else "releases"
            }
          )
        ),
        publishArtifact in Test := false
      )
    case other => Seq()
  }
}

lazy val commonSettings = publicationSettings  ++ Seq(
   name := "akka-http-signature",
   organization := "run.cosy",
   scalaVersion := "2.12.2",
   startYear := Some(2016)
)

commonSettings
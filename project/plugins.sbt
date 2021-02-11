logLevel := Level.Warn

// Typesafe Resolvers
resolvers += Resolver.typesafeRepo("releases")

// S3 based SBT resolver
resolvers ++= Seq(
  "HAT Library Artifacts Releases" at "https://s3-eu-west-1.amazonaws.com/library-artifacts-releases.hubofallthings.com",
  "HAT Library Artifacts Snapshots" at "https://s3-eu-west-1.amazonaws.com/library-artifacts-snapshots.hubofallthings.com"
)

libraryDependencies += "org.scala-lang" % "scala-compiler" % scalaVersion.value

addSbtPlugin("com.typesafe.sbt"  % "sbt-native-packager" % "1.7.1")
addSbtPlugin("com.typesafe.play" % "sbt-plugin"          % "2.7.5")

// Code Quality
addSbtPlugin("org.scoverage" % "sbt-scoverage" % "1.5.1")
addSbtPlugin("org.scoverage" % "sbt-coveralls" % "1.2.6")

// web plugins
addSbtPlugin("com.typesafe.sbt" % "sbt-web"     % "1.4.3")
addSbtPlugin("com.typesafe.sbt" % "sbt-digest"  % "1.1.4")
addSbtPlugin("com.typesafe.sbt" % "sbt-gzip"    % "1.0.2")
addSbtPlugin("org.irundaia.sbt" % "sbt-sassify" % "1.4.12")

addSbtPlugin("org.hatdex" % "sbt-slick-postgres-generator" % "0.0.11")

// run "sbt dependencyUpdates" to check maven for updates or "sbt ";dependencyUpdates; reload plugins; dependencyUpdates" for sbt plugins
addSbtPlugin("com.timushev.sbt" % "sbt-updates" % "0.3.4")

// ScalaFMT, ScalaFIX and Tools Common
addSbtPlugin("org.scalameta" % "sbt-scalafmt"        % "2.3.4")
addSbtPlugin("ch.epfl.scala" % "sbt-scalafix"        % "0.9.19")
addSbtPlugin("io.dataswift"  % "sbt-scalafmt-common" % "0.1.1")

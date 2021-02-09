/*
 * Copyright (C) 2017 HAT Data Exchange Ltd
 * SPDX-License-Identifier: AGPL-3.0
 *
 * This file is part of the Hub of All Things project (HAT).
 *
 * HAT is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License
 * as published by the Free Software Foundation, version 3 of
 * the License.
 *
 * HAT is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See
 * the GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General
 * Public License along with this program. If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Written by Andrius Aucinas <andrius.aucinas@hatdex.org>
 * 2 / 2017
 */

import sbt._

object Dependencies {

  object Versions {
    val crossScala   = Seq("2.12.11")
    val scalaVersion = crossScala.head
    val adjudicator  = "0.1.0-SNAPSHOT"
  }

  val resolvers = Seq(
    Resolver.jcenterRepo,
    "Atlassian Releases" at "https://maven.atlassian.com/public/",
    Resolver.bintrayRepo("scalaz", "releases"),
    Resolver.sonatypeRepo("snapshots"),
    "HAT Library Artifacts Snapshots" at "https://s3-eu-west-1.amazonaws.com/library-artifacts-snapshots.hubofallthings.com",
    "HAT Library Artifacts Releases" at "https://s3-eu-west-1.amazonaws.com/library-artifacts-releases.hubofallthings.com"
  )

  object Library {

    object Version {
      val Slf4jApi            = "1.7.30"
      val Sourcecode          = "0.2.3"
      val Jna                 = "5.6.0"
      val ScalaXml            = "1.3.0"
      val ScalaCheck          = "1.15.2"
      val Enumeratum          = "1.6.1"
      val ScalaTest           = "3.2.3"
      val TestContainersScala = "0.38.8"
      val ScalaMock           = "5.0.0"
    }

    object Play {
      val version     = play.core.PlayVersion.current
      val ws          = "com.typesafe.play" %% "play-ws"           % version
      val cache       = "com.typesafe.play" %% "play-cache"        % version
      val test        = "com.typesafe.play" %% "play-test"         % version
      val specs2      = "com.typesafe.play" %% "play-specs2"       % version
      val jdbc        = "com.typesafe.play" %% "play-jdbc"         % version
      val json        = "com.typesafe.play" %% "play-json"         % "2.6.14"
      val jsonJoda    = "com.typesafe.play" %% "play-json-joda"    % "2.6.14"
      val mailer      = "com.typesafe.play" %% "play-mailer"       % "6.0.1"
      val mailerGuice = "com.typesafe.play" %% "play-mailer-guice" % "6.0.1"

      val htmlCompressor = "com.mohiva"          %% "play-html-compressor" % "0.6.3"
      val playGuard      = "com.digitaltangible" %% "play-guard"           % "2.2.0"

      object Jwt {
        private val bouncyCastleVersion = "1.60"
        val bouncyCastle                = "org.bouncycastle"  % "bcprov-jdk15on" % bouncyCastleVersion
        val bouncyCastlePkix            = "org.bouncycastle"  % "bcpkix-jdk15on" % bouncyCastleVersion
        val atlassianJwtVersion         = "2.0.5"
        val atlassianJwtCore            = "com.atlassian.jwt" % "jwt-core"       % atlassianJwtVersion
      }

      object Silhouette {
        val version           = "5.1.4"
        val passwordBcrypt    = "com.mohiva" %% "play-silhouette-password-bcrypt" % version
        val persistence       = "com.mohiva" %% "play-silhouette-persistence"     % version
        val cryptoJca         = "com.mohiva" %% "play-silhouette-crypto-jca"      % version
        val silhouette        = "com.mohiva" %% "play-silhouette"                 % version
        val silhouetteTestkit = "com.mohiva" %% "play-silhouette-testkit"         % version % "test"
      }
    }

    object Specs2 {
      private val version = "4.10.0"
      val core            = "org.specs2" %% "specs2-core"          % version
      val matcherExtra    = "org.specs2" %% "specs2-matcher-extra" % version
      val mock            = "org.specs2" %% "specs2-mock"          % version
    }

    object Utils {
      private val awsSdkVersion    = "1.11.755"
      val pegdown                  = "org.pegdown"            % "pegdown"                         % "1.6.0"
      val awsJavaSdk               = "com.amazonaws"          % "aws-java-sdk"                    % awsSdkVersion
      val awsJavaS3Sdk             = "com.amazonaws"          % "aws-java-sdk-s3"                 % awsSdkVersion
      val prettyTime               = "org.ocpsoft.prettytime" % "prettytime"                      % "4.0.4.Final"
      val nbvcxz                   = "me.gosimple"            % "nbvcxz"                          % "1.4.3"
      val elasticacheClusterClient = "com.amazonaws"          % "elasticache-java-cluster-client" % "1.1.1"
      val playMemcached            = "com.github.mumoshu"    %% "play2-memcached-play26"          % "0.9.3" exclude ("net.spy", "spymemcached")
      val alpakkaAwsLambda         = "com.lightbend.akka"    %% "akka-stream-alpakka-awslambda"   % "0.20"
      val apacheCommonLang         = "org.apache.commons"     % "commons-lang3"                   % "3.10"
    }

    object HATDeX {
      val hatClient = "org.hatdex" %% "hat-client-scala-play" % "2.6.16"
      val dexClient = "org.hatdex" %% "dex-client-scala"      % "2.6.10"
      val codegen   = "org.hatdex" %% "slick-postgres-driver" % "0.0.9"
    }

    val scalaGuice  = "net.codingwell" %% "scala-guice"  % "4.2.6"
    val circeConfig = "io.circe"       %% "circe-config" % "0.8.0"

    object ContractLibrary {
      val adjudicator = "io.dataswift" %% "adjudicatorlib" % Versions.adjudicator
    }

    object Prometheus {
      val filters = "com.github.stijndehaes" %% "play-prometheus-filters" % "0.4.0"
    }

    object Test {
      val core = "org.scalatest" %% "scalatest" % Version.ScalaTest
    }

    object TestContainers {
      val scalaTest  = "com.dimafeng" %% "testcontainers-scala-scalatest"  % Version.TestContainersScala
      val postgresql = "com.dimafeng" %% "testcontainers-scala-postgresql" % Version.TestContainersScala
      val localstack = "com.dimafeng" %% "testcontainers-scala-localstack" % Version.TestContainersScala
    }

  }
}

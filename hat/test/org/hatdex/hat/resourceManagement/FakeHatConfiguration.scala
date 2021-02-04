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

package org.hatdex.hat.resourceManagement

object FakeHatConfiguration {
  def config =
    Map(
      "play.cache.createBoundCaches" -> "false",
      "resourceManagement.hatDBIdleTimeout" -> "30 seconds",
      "hat" -> Map(
            "hat.hubofallthings.net" -> Map(
                  "ownerEmail" -> "user@hat.org",
                  "database" -> Map(
                        "dataSourceClass" -> "org.postgresql.ds.PGSimpleDataSource",
                        "connectionPool" -> "disabled",
                        "properties" -> Map("databaseName" -> "test", "user" -> "test", "password" -> "test")
                      ),
                  "publicKey" -> """-----BEGIN PUBLIC KEY-----
          |MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAznT9VIjovMEB/hoZ9j+j
          |z9G+WWAsfj9IB7mAMQEICoLMWHC1ZnO4nrqTrRiQFKKrWekjhXFRp8jQZmGhv/sw
          |h5EsIcbRUzNNPSBmiCM0NXHG8wwN8cFigHXLQB0p4ekOWOHpEXfIZkTN5VlpUq1o
          |PdbgMXRW8NdU+Mwr7qQiUnHxaW0imFiahPs3n5Q3KLt2nWcxlvazeaRDphkEtFTk
          |JCaFx9TPzd1NSYpBidSMC2cwhVM6utaNk3ZRktCs+y0iFezL606x28P6+VuDkb19
          |6OxWEvSSxL3+1KQbKi3B9Hg/BNhigGsqQ35GzVPVygT7m90u9nNlxJ7KvfQDQc8t
          |dQIDAQAB
          |-----END PUBLIC KEY-----""".stripMargin,
                  "privateKey" -> """-----BEGIN RSA PRIVATE KEY-----
          |MIIEowIBAAKCAQEAznT9VIjovMEB/hoZ9j+jz9G+WWAsfj9IB7mAMQEICoLMWHC1
          |ZnO4nrqTrRiQFKKrWekjhXFRp8jQZmGhv/swh5EsIcbRUzNNPSBmiCM0NXHG8wwN
          |8cFigHXLQB0p4ekOWOHpEXfIZkTN5VlpUq1oPdbgMXRW8NdU+Mwr7qQiUnHxaW0i
          |mFiahPs3n5Q3KLt2nWcxlvazeaRDphkEtFTkJCaFx9TPzd1NSYpBidSMC2cwhVM6
          |utaNk3ZRktCs+y0iFezL606x28P6+VuDkb196OxWEvSSxL3+1KQbKi3B9Hg/BNhi
          |gGsqQ35GzVPVygT7m90u9nNlxJ7KvfQDQc8tdQIDAQABAoIBAF00Voub1UolbjNb
          |cD4Jw/fVrjPmJaAHDIskNRmqaAlqvDrvAw3SD1ZlT7b04FLYjzfjdvxOyLjRATg/
          |OkkT6vhA0yYafjSr8+I1JuSt0+uOxmzCE+eA0OnCg/QZVmedEbORpWkT5P46cKNq
          |RpCjJWzJfWQGLBvFcqBxeCHfqnkCFESRDG+YTUTzQ3Z4tdvXh/Wn7ZNAsJFaM2+x
          |krJF7bBas9MJ/A8fumtuickr6DpFB6/nQsKqou3wDsMPN9SeTgXAzvufnssK0bGx
          |8Z0F7pQUsl7CF2VuSXH2rcmW59JOpqPeZQ1JfrJZRxZ839vY+0BUF+Ti3FVJBb95
          |aXLqHF8CgYEA+vwJCI6y+W/Cfwu79ssoJB+038sJftqkpKcFCipTsvX26h8o5+Vd
          |BSvo58cjbXSV6a7PevkQvlgpKPki9SZnE+LoEmq1KbmN6yV0kev4Kzmi7P9Lz1Z8
          |XRkt5KWQSMn65ZhLRHeomM71TgzDye1QI6rIKp4oumZUrlj8xGPB7VMCgYEA0pUq
          |DSprxCQajw5WiH9X2sswrzDuK/+YAPZFBcRkK2KS9KGkltqlU9EmfZSX794vqfZw
          |WBzJMRvxy0tF9QYSFahGivk98dzUUfARx79lIrKDBRVeUuP5LQ762K7BhDanym5a
          |4YvzRPsJGHUT6Kyn1nsoP/CXqr1fxbv/HaN7WRcCgYEAz+x+O1WklZptobyB4kmZ
          |npuZx5C39ByEK1emiC5amrbD8F8SD1LnhgJDd8h05Beini5Q+opdwaLdrnD+8eL3
          |n/Tp12AJZ2CuXrDv6nd3Z6/e9sHk9waqDqJub65tYq/Zp91L9ZO/26AQfrF6fc2Z
          |B4NTQmM2UH24B5v3A2e1X7sCgYBXnFuMcrO3PNYX4n05+NESZCrzGEZe483XyJ3a
          |0mRicHZ3dLDHWlwiTQfYg3PbBfOKoM8IuaEy309vpveKA2aOwB3pP9z3vUpQdLLR
          |Cd4H24ELImLF1bcbefn/IGW+ngac/+CrqdAiSNb15+/Kg9qoL0EFqRFQpc0stRRk
          |vllZLQKBgEuos9IFTnXvF5+NpwQJ54t4YQW/StgPL7sPVA86irXnuT3VwdVNg2VF
          |AZa/LU3jAXt2iTziR0LTKueamj/V+YM4qVyc/LhUPvjKlsCjyLBb647p3C/ogYbj
          |mO9kGhALaD5okBcI/VuAQiFvBXdK0ii/nVcBApXEu47PG4oYUgPI
          |-----END RSA PRIVATE KEY-----""".stripMargin
                )
          )
    )
}

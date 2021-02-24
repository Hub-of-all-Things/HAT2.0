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
 * 5 / 2017
 */

package org.hatdex.hat.api.service.richData

import java.security.MessageDigest
import java.util.UUID
import javax.inject.Inject

import scala.annotation.tailrec
import scala.collection.immutable.HashMap
import scala.concurrent.Future
import scala.util.Success

import akka.stream.SubstreamCancelStrategy
import akka.stream.scaladsl.Source
import akka.{ Done, NotUsed }
import io.dataswift.models.hat._
import org.hatdex.hat.api.service.DalExecutionContext
import org.hatdex.hat.dal.ModelTranslation
import org.hatdex.hat.dal.Tables._
import org.hatdex.hat.utils.Utils
import org.hatdex.libs.dal.HATPostgresProfile.api._
import org.joda.time.{ DateTime, LocalDateTime }
import org.postgresql.util.PSQLException
import play.api.Logger
import play.api.libs.json._

class RichDataService @Inject() (implicit ec: DalExecutionContext) {

  protected val logger: Logger = Logger(this.getClass)

  private def dbDataRow(
      endpoint: String,
      userId: UUID,
      data: JsValue,
      recordId: Option[UUID] = None): DataJsonRow = {
    val md     = MessageDigest.getInstance("SHA-256")
    val digest = md.digest(data.toString.getBytes)
    DataJsonRow(
      recordId.getOrElse(UUID.randomUUID()),
      endpoint,
      userId,
      LocalDateTime.now(),
      data,
      digest
    )
  }

  private def saveDataQuery(
      userId: UUID,
      endpointData: Seq[EndpointData],
      linkedRecords: Option[Seq[UUID]]) = {
    val queries = endpointData map { endpointDataGroup =>
      val endpointRow =
        dbDataRow(endpointDataGroup.endpoint, userId, endpointDataGroup.data)

      val linkedRows = endpointDataGroup.links
        .map(_.toList)
        .getOrElse(List())
        .map(i => dbDataRow(i.endpoint, userId, i.data))

      val recordIds = endpointRow.recordId :: linkedRows.map(_.recordId)

      val (groupRow, groupRecordRows) = if (recordIds.length > 1) {
        val groupRow =
          DataJsonGroupsRow(UUID.randomUUID(), userId, LocalDateTime.now())
        val groupRecordRows =
          recordIds.map(DataJsonGroupRecordsRow(groupRow.groupId, _)) ++
              linkedRecords
                .map(r => r.map(DataJsonGroupRecordsRow(groupRow.groupId, _)))
                .getOrElse(Seq())
        (Seq(groupRow), groupRecordRows)
      } else
        (Seq(), Seq())

      for {
        endpointData <- (DataJson returning DataJson) += endpointRow
        linkedData <- (DataJson returning DataJson) ++= linkedRows
        group <- DataJsonGroups ++= groupRow
        groupRecords <- DataJsonGroupRecords ++= groupRecordRows
      } yield (endpointData, linkedData, group, groupRecords)
    }
    queries
  }

  def saveData(
      userId: UUID,
      endpointData: Seq[EndpointData],
      skipErrors: Boolean = false
    )(implicit db: Database): Future[Seq[EndpointData]] = {
    val queries = saveDataQuery(userId, endpointData, None)

    val insertQuery = if (skipErrors) {
      val temp = queries.map(q => q.asTry)
      db.run(DBIO.sequence(temp))
        .map {
          _.collect {
            case Success(d) => d
          }
        }
    } else
      db.run(DBIO.sequence(queries).transactionally)

    insertQuery
      .map {
        _.map { inserted =>
          ModelTranslation.fromDbModel(inserted._1, inserted._2)
        }
      } recover {
      case e: PSQLException
          if e.getMessage.startsWith(
            "ERROR: duplicate key value violates unique constraint \"data_json_hash_key\""
          ) =>
        throw RichDataDuplicateException("Duplicate data", e)
      case e: PSQLException =>
        throw RichDataDuplicateException(
          "Unexpected issue with inserting data",
          e
        )
    }
  }

  def saveDataGroups(
      userId: UUID,
      dataGroups: Seq[(Seq[EndpointData], Seq[UUID])],
      skipErrors: Boolean = false
    )(implicit db: Database): Future[Seq[EndpointData]] = {
    val queries = dataGroups flatMap {
          case (endpointData, linkedRecords) =>
            saveDataQuery(userId, endpointData, Some(linkedRecords))
        }

    val insertAction = if (skipErrors) {
      val temp = queries.map(q => q.asTry)
      db.run(DBIO.sequence(temp))
        .map {
          _.collect {
            case Success(d) => d
          }
        }
    } else
      db.run(DBIO.sequence(queries).transactionally)

    insertAction
      .map {
        _.map { inserted =>
          ModelTranslation.fromDbModel(inserted._1, inserted._2)
        }
      } recover {
      case e: PSQLException
          if e.getMessage.startsWith(
            "ERROR: duplicate key value violates unique constraint \"data_json_hash_key\""
          ) =>
        throw RichDataDuplicateException("Duplicate data", e)
      case e: PSQLException =>
        throw RichDataDuplicateException(
          "Unexpected issue with inserting data",
          e
        )
    }
  }

  def listEndpoints(
    )(implicit db: Database): Future[Map[String, Seq[String]]] = {
    val query = DataJson.map(_.source).distinct
    db.run(query.result).map { sources =>
      sources
        .map { s =>
          val parts = s.split('/')
          (parts.head, parts.tail.mkString("/"))
        }
        .groupBy(_._1)
        .map { case (k, v) => k -> v.unzip._2 }
    }
  }

  def deleteEndpoint(
      dataEndpoint: String
    )(implicit db: Database): Future[Done] = {
    val endpointRecordsQuery =
      DataJson.filter(r => r.source === dataEndpoint).map(_.recordId)
    val query = for {
      deletedGroupRecords <- DataJsonGroupRecords
                               .filter(_.recordId in endpointRecordsQuery)
                               .delete // delete links between records and groups
      deletedGroups <- DataJsonGroups
                         .filterNot(g => g.groupId in DataJsonGroupRecords.map(_.groupId))
                         .delete // delete any groups that have become empty
      deletedRecords <- DataJson
                          .filter(r => r.recordId in endpointRecordsQuery)
                          .delete // delete the records, but only if all requested records are found
    } yield (deletedGroupRecords, deletedGroups, deletedRecords)

    db.run(query.transactionally).map(_ => Done) recover {
      case e: NoSuchElementException =>
        throw RichDataMissingException("Records missing for deleting", e)
    }
  }

  def uniqueRecordNamespaces(
      recordIds: Seq[UUID]
    )(implicit db: Database): Future[Set[String]] = {
    val uniqueEndpointQuery = DataJson
      .filter(r => r.recordId inSet recordIds)
      .map(_.source)
      .distinct

    db.run(uniqueEndpointQuery.result)
      .map(endpoints => endpoints.flatMap(_.split("/").headOption).toSet)
  }

  def deleteRecords(
      userId: UUID,
      recordIds: Seq[UUID]
    )(implicit db: Database): Future[Unit] = {
    val query = for {
      deletedGroupRecords <- DataJsonGroupRecords
                               .filter(_.recordId inSet recordIds)
                               .delete // delete links between records and groups
      deletedGroups <- DataJsonGroups
                         .filterNot(g =>
                           (g.owner === userId) && (g.groupId in DataJsonGroupRecords
                                   .map(_.groupId))
                         )
                         .delete // delete any groups that have become empty
      deletedRecords <- DataJson
                          .filter(r => (r.owner === userId) && (r.recordId inSet recordIds))
                          .delete
      if deletedRecords == recordIds.length // delete the records, but only if all requested records are found
    } yield (deletedGroupRecords, deletedGroups, deletedRecords)

    db.run(query.transactionally).map(_ => ()) recover {
      case e: NoSuchElementException =>
        throw RichDataMissingException("Records missing for deleting", e)
    }
  }

  def updateRecords(
      userId: UUID,
      records: Seq[EndpointData]
    )(implicit db: Database): Future[Seq[EndpointData]] = {
    val updateRows = records.map { record =>
      dbDataRow(record.endpoint, userId, record.data, record.recordId)
    }

    val updateQueries = updateRows map { record =>
      for {
        updated <- DataJson
                     .filter(r => r.recordId === record.recordId && r.owner === userId)
                     .map(r => (r.data, r.date, r.hash))
                     .update((record.data, record.date, record.hash)) if updated == 1
      } yield updated
    }

    db.run(DBIO.sequence(updateQueries).transactionally).map { _ =>
      updateRows.map(ModelTranslation.fromDbModel)
    } recover {
      case e: NoSuchElementException =>
        throw RichDataMissingException("Records missing for updating", e)
    }
  }

  def saveRecordGroup(
      userId: UUID,
      recordIds: Seq[UUID]
    )(implicit db: Database): Future[UUID] = {
    val groupRow =
      DataJsonGroupsRow(UUID.randomUUID(), userId, LocalDateTime.now())
    val groupRecordRows =
      recordIds.map(DataJsonGroupRecordsRow(groupRow.groupId, _))

    val query = for {
      group <- DataJsonGroups += groupRow
      groupRecords <- DataJsonGroupRecords ++= groupRecordRows
    } yield (group, groupRecords)

    db.run(query.transactionally)
      .map { _ =>
        groupRow.groupId
      }
  }

  private def queryMappers(
      endpointQueries: Seq[EndpointQuery]): HashMap[String, Reads[JsObject]] = {
    val mappers = endpointQueries.zipWithIndex flatMap {
          case (endpointQuery, index) =>
            val id = index.toString
            val transformer = endpointQuery.mapping collect {
                  case m: JsObject => id -> JsonDataTransformer.mappingTransformer(m)
                }
            val subTransformers =
              endpointQuery.links.getOrElse(Seq()).zipWithIndex.map {
                case (link, subIndex) =>
                  link.mapping collect {
                      case m: JsObject =>
                        s"$id-$subIndex" -> JsonDataTransformer.mappingTransformer(m)
                    }
              }
            (subTransformers :+ transformer).flatten
        }
    HashMap(mappers: _*)
  }

  protected[service] def generatedDataQuery(
      endpointQuery: EndpointQuery,
      query: Query[DataJson, DataJsonRow, Seq]): Query[DataJson, DataJsonRow, Seq] = {
    val q = query.filter(_.source === endpointQuery.endpoint)
    endpointQuery.filters map { filters =>
      generateDataQueryFiltered(filters, q)
    } getOrElse {
      q
    }
  }

  private def generateDataQueryFiltered(
      filters: Seq[EndpointQueryFilter],
      query: Query[DataJson, DataJsonRow, Seq]): Query[DataJson, DataJsonRow, Seq] =
    if (filters.isEmpty)
      query
    else {
      val currentQuery = processQueryFilter(filters.head, query)
      generateDataQueryFiltered(filters.tail, currentQuery)
    }

  def processQueryFilter(
      filter: EndpointQueryFilter,
      query: Query[DataJson, DataJsonRow, Seq]): Query[DataJson, DataJsonRow, Seq] = {
    import FieldTransformation._
    import FilterOperator._

    val currentTransformation =
      filter.transformation.getOrElse(FieldTransformation.Identity())
    filter.operator match {
      case Contains(value) =>
        currentTransformation match {
          case t: Identity =>
            def f: Rep[JsValue] => Rep[JsValue] = FieldTransformable.process(t)

            query.filter(d => f(d.data #> filter.originalField) @> value)
          case t: DateTimeExtract =>
            def f: Rep[JsValue] => Rep[JsValue] = FieldTransformable.process(t)

            query.filter(d => f(d.data #> filter.originalField) @> value)
          case t: TimestampExtract =>
            def f: Rep[JsValue] => Rep[JsValue] = FieldTransformable.process(t)

            query.filter(d => f(d.data #> filter.originalField) @> value)
          case _ => query
        }

      case In(value) =>
        currentTransformation match {
          case t: Identity =>
            def f: Rep[JsValue] => Rep[JsValue] = FieldTransformable.process(t)

            query.filter(d => value <@: f(d.data #> filter.originalField))
          case t: DateTimeExtract =>
            def f: Rep[JsValue] => Rep[JsValue] = FieldTransformable.process(t)

            query.filter(d => value <@: f(d.data #> filter.originalField))
          case t: TimestampExtract =>
            def f: Rep[JsValue] => Rep[JsValue] = FieldTransformable.process(t)

            query.filter(d => value <@: f(d.data #> filter.originalField))
          case _ => query
        }

      case Between(lower, upper) =>
        currentTransformation match {
          case t: Identity =>
            def f: Rep[JsValue] => Rep[JsValue] = FieldTransformable.process(t)

            query.filter(d => f(d.data #> filter.originalField) between (lower, upper))
          case t: DateTimeExtract =>
            def f: Rep[JsValue] => Rep[JsValue] = FieldTransformable.process(t)

            query.filter(d => f(d.data #> filter.originalField) between (lower, upper))
          case t: TimestampExtract =>
            def f: Rep[JsValue] => Rep[JsValue] = FieldTransformable.process(t)

            query.filter(d => f(d.data #> filter.originalField) between (lower, upper))
          case _ => query
        }

      case Find(searchTerm) =>
        currentTransformation match {
          case t: Searchable =>
            val f = FieldTransformable.process(t)
            query.filter(d =>
              f(d.data #> filter.originalField) @@ plainToTsQuery(
                    LiteralColumn(searchTerm.toString)
                  )
            )
          case _ => query
        }
    }
  }

  /**
    * @param endpointQueries List of endpoint queries to fetch data for
    * @param orderBy Optional ordering to apply on the data - creation date by default
    * @return the generated query for a list of data records, for each record including the JSON Data row, , and if present - same for linked records
    */
  private def propertyDataQuery(
      endpointQueries: Seq[EndpointQuery],
      orderBy: Option[String],
      orderingDescending: Boolean,
      skip: Int,
      limit: Option[Int],
      createdAfter: Option[DateTime]): Query[_, ((DataJsonRow, Int), Option[(DataJsonRow, String)]), Seq] = {
    val queriesWithMappers = endpointQueries.zipWithIndex map {
          case (endpointQuery, endpointQueryIndex) =>
            orderBy map { orderBy =>
              for {
                data <- generatedDataQuery(endpointQuery, DataJson)
              } yield (
                data,
                data.data #> endpointQuery.originalField(orderBy),
                endpointQueryIndex.bind
              ) // Include the data, the selected sort field and endpoint query index for later joins
            } getOrElse {
              for {
                data <- generatedDataQuery(endpointQuery, DataJson)
              } yield (
                data,
                toJsonGenericOptional(data.date),
                endpointQueryIndex.bind
              ) // Include the data, the date field as the sort field and endpoint query index for later joins
            }
        }

    val endpointDataQuery = queriesWithMappers
      .reduce((aggregate, query) => aggregate.unionAll(query)) // merge all the queries together
      .sortBy(d =>
        if (orderingDescending)
          d._2.desc.nullsLast
        else
          d._2.asc.nullsLast
      ) // order all the results by the chosen column
      .filter(d => createdAfter.fold(true.bind)(t => d._1.date > t.toLocalDateTime))

    val endpointDataQueryWithLimits = limit map { take =>
      endpointDataQuery
        .drop(skip) // skip the desired number of records
        .take(take) // take up to the desired number of records
    } getOrElse {
      endpointDataQuery
        .drop(skip) // skip the desired number of records
    }

    val linkedRecordQueries =
      endpointQueries.zipWithIndex map { // linked records are tracked separately for each query, use index to disambiguate
          case (endpointQuery, endpointQueryIndex) =>
            endpointQuery.links map { links => // for each endpoint query, track links separately, via the link ID
              links.zipWithIndex map {
                case (link, linkIndex) =>
                  for {
                    endpointQueryRecordGroup <- DataJsonGroupRecords // Get the JSON groups
                    (linkedGroupId, linkedRecordId) <- DataJsonGroupRecords.map(v => (v.groupId, v.recordId))
                    if endpointQueryRecordGroup.groupId === linkedGroupId && endpointQueryRecordGroup.recordId =!= linkedRecordId // Pick out the group IDs and record IDs that match
                    linkedRecord <- generatedDataQuery(
                                      link,
                                      DataJson.filter(_.recordId === linkedRecordId)
                                    ) // Pull out the records themselves, following on foreign-keyed IDs
                  } yield (
                    endpointQueryIndex,
                    s"$endpointQueryIndex-$linkIndex".bind,
                    endpointQueryRecordGroup.recordId,
                    linkedRecord
                  ) // Include the endpoint query index, generate the name of the link, the record ID to link from, and the record itself
              }
            } getOrElse { // generate dummy, empty query for the join operation next
              Seq(
                for {
                  noGroup <- DataJsonGroupRecords.take(0) // take no group records
                  noLinkedRecord <- DataJson.take(0) // take no linked records
                } yield (
                  endpointQueryIndex,
                  s"$endpointQueryIndex-".bind,
                  noGroup.recordId,
                  noLinkedRecord
                )
              )
            }
        }

    val groupRecords = linkedRecordQueries.flatten
      .reduce((aggregate, query) => aggregate.unionAll(query))

    val resultQuery = endpointDataQueryWithLimits
      .joinLeft(groupRecords)
      .on((l, r) =>
        l._1.recordId === r._3 && l._3 === r._1
      ) // join on the main query record ID with the linked query record ID AND the query index
      .sortBy(
        if (orderingDescending)
          _._1._2.desc.nullsLast
        else
          _._1._2.asc.nullsLast
      ) // join does not maintain data ordering - sort data by the chosen sort field
      .map(v => ((v._1._1, v._1._3), v._2.map(lr => (lr._4, lr._2)))) // pull out only the required data

    resultQuery
  }

  implicit def equalDataJsonRowIdentity(
      a: (DataJsonRow, Int),
      b: (DataJsonRow, Int)): Boolean =
    a._1.recordId == b._1.recordId

  @tailrec
  private def groupRecords[T, U](
      list: Seq[(T, Option[U])],
      groups: Seq[(T, Seq[U])] = Seq()
    )(implicit equalIdentity: ((T, T) => Boolean)): Seq[(T, Seq[U])] =
    if (list.isEmpty)
      groups
    else
      groupRecords(
        list.dropWhile(v => equalIdentity(v._1, list.head._1)),
        groups :+ (
              (
                list.head._1,
                list
                  .takeWhile(v => equalIdentity(v._1, list.head._1))
                  .unzip
                  ._2
                  .flatten
              )
            )
      )

  def propertyDataMostRecentDate(
      endpointQueries: Seq[EndpointQuery]
    )(implicit db: Database): Future[Option[DateTime]] = {
    val query = propertyDataQuery(
      endpointQueries,
      None,
      orderingDescending = true,
      0,
      Some(1),
      None
    )

    db.run(query.result).map { results =>
      results.headOption.map(_._1._1.date.toDateTime)
    }
  }

  def propertyData(
      endpointQueries: Seq[EndpointQuery],
      orderBy: Option[String],
      orderingDescending: Boolean,
      skip: Int,
      limit: Option[Int],
      createdAfter: Option[DateTime] = None
    )(implicit db: Database): Future[Seq[EndpointData]] = {

    val query = propertyDataQuery(
      endpointQueries,
      orderBy,
      orderingDescending,
      skip,
      limit,
      createdAfter
    )
    val mappers = queryMappers(endpointQueries)

    db.run(query.result).map { results =>
      groupRecords[(DataJsonRow, Int), (DataJsonRow, String)](results).map {
        case ((record, queryId), linkedResults) =>
          val linked = linkedResults.map {
            case (linkedRecord, linkedQueryId) =>
              endpointDataWithMappers(linkedRecord, linkedQueryId, mappers)
          }
          val endpointData =
            endpointDataWithMappers(record, queryId.toString, mappers)
          if (linked.nonEmpty)
            endpointData.copy(links = Some(linked))
          else
            endpointData
      }
    } recover {
      case e: PSQLException if e.getMessage.contains("cannot cast type") =>
        throw RichDataBundleFormatException(
          "Invalid bundle format - cannot cast between types to satisfy query",
          e
        )
    }
  }

  def propertyDataStreaming(
      endpointQueries: Seq[EndpointQuery],
      orderBy: Option[String],
      orderingDescending: Boolean,
      skip: Int,
      limit: Option[Int],
      createdAfter: Option[DateTime] = None
    )(implicit db: Database): Source[EndpointData, NotUsed] = {

    val query = propertyDataQuery(
      endpointQueries,
      orderBy,
      orderingDescending,
      skip,
      limit,
      createdAfter
    )
    val mappers = queryMappers(endpointQueries)

    val zerouuid = UUID.fromString("00000000-0000-0000-0000-000000000000")
    val zerothItem: ((DataJsonRow, Int), Option[(DataJsonRow, String)]) = (
      (
        DataJsonRow(
          zerouuid,
          "",
          zerouuid,
          LocalDateTime.now(),
          JsNull,
          Array[Byte]()
        ),
        0
      ),
      Option[(DataJsonRow, String)](null)
    )

    Source
      .fromPublisher(
        db.stream(
          query.result.transactionally.withStatementParameters(fetchSize = 500)
        )
      )
      .prepend(Source.single(zerothItem))
      .sliding(2, 1)
      .splitWhen(SubstreamCancelStrategy.drain)(w =>
        w.head._1._1.recordId != w.last._1._1.recordId
      ) // items arrive ordered by record id, all items with same record ID on the left form part of the same group
      .map(w => (w.last._1, w.last._2.map(Seq(_)).getOrElse(Seq()))) // remap linked items from optionals to lists
      .reduce((acc, next) => (acc._1, acc._2 ++ next._2)) // reduce the whole substream to one item
      .concatSubstreams // concatenate substreams allowing to run only one substream at a time - substreams happen sequentially anyway
      .collect({
        case ((record, queryId), linkedResults) =>
          val linked =
            linkedResults.map(l => endpointDataWithMappers(l._1, l._2, mappers))
          endpointDataWithMappers(record, queryId.toString, mappers)
            .copy(links = Utils.seqOption(linked))
      })
      .recover {
        case e: PSQLException if e.getMessage.contains("cannot cast type") =>
          throw RichDataBundleFormatException(
            "Invalid bundle format - cannot cast between types to satisfy query",
            e
          )
      }
  }

  private def endpointDataWithMappers(
      record: DataJsonRow,
      queryId: String,
      mappers: HashMap[String, Reads[JsObject]]): EndpointData =
    EndpointData(
      record.source,
      Some(record.recordId),
      record.sourceTimestamp,
      record.sourceUniqueId,
      mappers
        .get(queryId)
        .map(
          record.data.transform
        ) // apply JSON transformation if it is present
        .map(
          _.getOrElse(Json.obj())
        ) // quietly empty object of transformation fails
        .getOrElse(record.data), // if no mapper, return data as-is
      None
    )

  def bundleData(
      bundle: EndpointDataBundle,
      skip: Option[Int] = None,
      limit: Option[Int] = None,
      createdAfter: Option[DateTime] = None
    )(implicit db: Database): Future[Map[String, Seq[EndpointData]]] = {
    val results = bundle.bundle map {
          case (property, propertyQuery) =>
            val skipRecords = skip.getOrElse(0)
            val takeRecords = propertyQuery
            // if bundle has a limit, reduce the take by records already skipped,
            // otherwise take the smaller of it and the provided limit
            .limit
              .map(l => Math.max(Math.min(l - skipRecords, limit.getOrElse(l)), 0))
              // if no limit, take the provided one
              .orElse(limit)

            propertyData(
              propertyQuery.endpoints,
              propertyQuery.orderBy,
              orderingDescending = propertyQuery.ordering.contains("descending"),
              skipRecords,
              takeRecords,
              createdAfter
            )
              .map(property -> _)
        }

    Future.foldLeft(results)(Map[String, Seq[EndpointData]]()) { (propertyMap, response) =>
      propertyMap + response
    }
  }

}

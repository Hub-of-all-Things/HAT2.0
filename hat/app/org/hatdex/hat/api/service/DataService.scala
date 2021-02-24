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
package org.hatdex.hat.api.service

import scala.concurrent.{ ExecutionContext, Future }

import io.dataswift.models.hat.{ ApiDataField, ApiDataRecord, ApiDataTable, ApiDataValue }
import org.hatdex.hat.dal.ModelTranslation
import org.hatdex.hat.dal.Tables._
import org.hatdex.libs.dal.HATPostgresProfile.api._

object DataService {
  protected[service] def buildTableStructure(
      table: ApiDataTable,
      fields: Seq[ApiDataField],
      dataTables: Seq[(ApiDataTable, Option[Int])]): ApiDataTable = {
    val tableFields = {
      val tFields = fields.filter(_.tableId == table.id)
      if (tFields.isEmpty)
        None
      else
        Some(tFields)
    }
    val subtables = dataTables.filter(tablePair => table.id == tablePair._2)
    val apiTables = subtables.map { apiTable =>
      // Every subtable with a linked ID exists, no need to handle Option
      buildTableStructure(apiTable._1, fields, dataTables)
    }
    val someApiTables =
      if (apiTables.isEmpty)
        None
      else
        Some(apiTables)
    table.copy(fields = tableFields, subTables = someApiTables)
  }

  protected[hat] def getStructureFields(structure: ApiDataTable): Set[Int] = {
    val fieldSet = structure.fields.getOrElse(Seq()).flatMap(_.id).toSet

    structure.subTables
      .getOrElse(Seq())
      .map(getStructureFields)
      .fold(fieldSet)((fieldset, subtableFieldset) => fieldset ++ subtableFieldset)
  }

  protected[hat] def restructureTableValuesToRecords(
      dbValues: Seq[(DataRecordRow, DataFieldRow, DataValueRow)],
      tables: Seq[ApiDataTable]): Seq[ApiDataRecord] = {

    // Group values by record
    val byRecord = dbValues.groupBy(_._1)

    val records = byRecord flatMap {
          case (
                record,
                recordValues: Seq[(DataRecordRow, DataFieldRow, DataValueRow)]
              ) =>
            val fieldValues = recordValues
              .map { case (_, f, v) => (f, v) }
              .groupBy(_._1.id) // Group values by field
              .map {
                case (k, v) => (k, v.unzip._2.map(ModelTranslation.fromDbModel))
              }

            val filledRecords = tables.flatMap { table =>
              val filledValues = fillStructure(table)(fieldValues)
              if (
                filledValues.fields.isDefined && filledValues.fields.get.nonEmpty ||
                filledValues.subTables.isDefined && filledValues.subTables.get.nonEmpty
              )
                // Keep records separate for each root table
                Some(ModelTranslation.fromDbModel(record, Some(Seq(filledValues))))
              else
                None
            }
            filledRecords
        }

    records.toSeq.sortBy(-_.id.getOrElse(0))
  }

  /*
   * Fills ApiDataTable with values grouped by field ID
   */
  protected def fillStructure(
      table: ApiDataTable
    )(values: Map[Int, Seq[ApiDataValue]]): ApiDataTable = {
    val filledFields = table.fields map { fields =>
      // For each field, insert values
      fields.collect {
        case ApiDataField(
              Some(fieldId),
              dateCreated,
              lastUpdated,
              tableId,
              fieldName,
              _
            ) =>
          val fieldValues = values.get(fieldId)
          fieldValues.map { fValues =>
            // Create a new field with only the values updated
            ApiDataField(
              Some(fieldId),
              dateCreated,
              lastUpdated,
              tableId,
              fieldName,
              Some(fValues)
            )
          }
      }.flatten
    }

    val filledSubtables = table.subTables map { subtables =>
      val filled = subtables map { subtable: ApiDataTable =>
        fillStructure(subtable)(values)
      }
      val nonEmpty = filled.filter { t =>
        (t.fields.nonEmpty && t.fields.get.nonEmpty) || (t.subTables.nonEmpty && t.subTables.get.nonEmpty)
      }
      nonEmpty
    }

    table.copy(fields = filledFields, subTables = filledSubtables)
  }

  protected[api] def buildDataTreeStructures(
      dataTableTrees: Query[DataTableTree, DataTableTreeRow, Seq],
      roots: Set[Int] = Set()
    )(implicit db: Database,
      ec: ExecutionContext): Future[Seq[ApiDataTable]] = {

    // Another round of field filtering to only get those within the returned trees
    val treeFieldQuery = for {
      (tree, maybeField) <- dataTableTrees joinLeft DataField.filter(_.deleted === false)
    } yield (tree, maybeField)

    val eventualTreeFields = db.run(treeFieldQuery.result)

    eventualTreeFields.map { treeFields =>
      val tablesWithParents = treeFields
        .map(_._1) // Get the trees
        .map(tree =>
          (ModelTranslation.fromDbModel(tree, None, None), tree.table1)
        ) // Use the API data model for each tree
        .distinct // Take only distinct trees (duplicates are returned with each field
      //logger.debug(s"Got tables with parents: $tablesWithParents")

      val fields = treeFields
        .flatMap(_._2)
        .map(ModelTranslation.fromDbModel)
        .distinct

      val rootTables =
        if (roots.nonEmpty)
          tablesWithParents.filter(t => roots.contains(t._1.id.get)).map(_._1)
        else
          tablesWithParents.filter(_._2.isEmpty).map(_._1)

      rootTables map { table =>
        buildTableStructure(table, fields, tablesWithParents)
      }
    }
  }

}

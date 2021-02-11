package org.hatdex.hat.fixtures

import org.scalamock.scalatest.MockFactory
import play.api.i18n.MessagesApi
import play.api.mvc._

import scala.concurrent.ExecutionContext.Implicits.global

trait PlayControllerFixture extends MockFactory {
  val components: ControllerComponents                  = stub[ControllerComponents]
  val messagesApi: MessagesApi                          = stub[MessagesApi]
  val bodyParser: BodyParser[AnyContent]                = stub[BodyParser[AnyContent]]
  val actionBuilder: ActionBuilder[Request, AnyContent] = new ActionBuilderImpl(bodyParser)
  (() => components.actionBuilder).when().returning(actionBuilder)
  (() => components.messagesApi).when().returning(messagesApi)
}

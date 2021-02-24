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
 * 11 / 2017
 */

package org.hatdex.hat.she.functions

import io.dataswift.models.hat.json.RichDataJsonFormats
import io.dataswift.models.hat.EndpointData
import org.hatdex.hat.she.service.FunctionServiceContext
import play.api.libs.json.{ Format, Json }

trait DataFeedDirectMapperContext extends FunctionServiceContext {
  implicit private val endpointDataFormat: Format[EndpointData] = RichDataJsonFormats.endpointDataFormat

  private val exampleTweetRetweetText =
    """
      |{
      |        "endpoint": "twitter/tweets",
      |        "recordId": "ca73e78d-e5de-4742-80da-29b53b37f361",
      |        "data": {
      |            "id": "911521736813875200",
      |            "lang": "en",
      |            "text": "RT @jupenur: Oh shit Adobe https://t.co/7rDL3LWVVz",
      |            "user": {
      |                "id": "82142104",
      |                "lang": "en",
      |                "name": "Andrius Aucinas",
      |                "screen_name": "AndriusAuc",
      |                "listed_count": "24",
      |                "friends_count": "252",
      |                "statuses_count": "1561",
      |                "followers_count": "235",
      |                "favourites_count": "39"
      |            },
      |            "source": "<a href=\"http://twitter.com/download/iphone\" rel=\"nofollow\">Twitter for iPhone</a>",
      |            "favorited": false,
      |            "retweeted": true,
      |            "truncated": false,
      |            "created_at": "Sat Sep 23 09:24:51 +0000 2017",
      |            "lastUpdated": "2017-09-20T09:24:51+0000",
      |            "retweet_count": "2937",
      |            "favorite_count": "0",
      |            "possibly_sensitive": "false",
      |            "coordinates": {
      |              "coordinates":
      |               [
      |                 -75.14310264,
      |                 40.05701649
      |               ],
      |               "type":"Point"
      |            },
      |            "place": {
      |              "attributes":{},
      |              "bounding_box": {
      |               "coordinates":
      |                 [[
      |                 [-77.119759,38.791645],
      |                 [-76.909393,38.791645],
      |                 [-76.909393,38.995548],
      |                 [-77.119759,38.995548]
      |                 ]],
      |               "type":"Polygon"
      |              },
      |              "country":"United States",
      |              "country_code":"US",
      |              "full_name":"Washington, DC",
      |              "id":"01fbe706f872cb32",
      |              "name":"Washington",
      |              "place_type":"city",
      |              "url": "http://api.twitter.com/1/geo/id/01fbe706f872cb32.json"
      |            }
      |        }
      |    }
    """.stripMargin

  val exampleTweetRetweet: EndpointData = Json.parse(exampleTweetRetweetText).as[EndpointData]

  private val exampleTweetMentionsText =
    """
      |{
      |        "endpoint": "twitter/tweets",
      |        "recordId": "a1fffbea-4aa0-4dfb-a6e7-bd14afd29263",
      |        "data": {
      |            "id": "911672713936343040",
      |            "lang": "en",
      |            "text": "@drgeep Don't forget transitive trust is hard in reality. E.g in international transfers between thousands of rando… https://t.co/uTQPsoKfrD",
      |            "user": {
      |                "id": "82142104",
      |                "lang": "en",
      |                "name": "Andrius Aucinas",
      |                "screen_name": "AndriusAuc",
      |                "listed_count": "24",
      |                "friends_count": "252",
      |                "statuses_count": "1564",
      |                "followers_count": "235",
      |                "favourites_count": "39"
      |            },
      |            "source": "<a href=\"http://twitter.com/download/iphone\" rel=\"nofollow\">Twitter for iPhone</a>",
      |            "favorited": false,
      |            "retweeted": false,
      |            "truncated": true,
      |            "created_at": "Sat Sep 23 19:24:47 +0000 2017",
      |            "lastUpdated": "2017-09-23T19:24:47+0000",
      |            "retweet_count": "0",
      |            "favorite_count": "1",
      |            "in_reply_to_user_id": "29676252",
      |            "in_reply_to_status_id": "911617143032238080",
      |            "in_reply_to_screen_name": "drgeep"
      |        }
      |    }
    """.stripMargin

  val exampleTweetMentions: EndpointData = Json.parse(exampleTweetMentionsText).as[EndpointData]

  private val exampleTweetMinimalFieldsText =
    """
      |{
      |        "endpoint": "twitter/tweets",
      |        "recordId": "8c9c541c-21e5-4094-875d-ede01c9bf613",
      |        "data": {
      |            "id": 953685879859679233,
      |            "geo": null,
      |            "lang": "en",
      |            "text": "Tweet from Portugal.",
      |            "user": {
      |                "id": 819125281931792384,
      |                "url": null,
      |                "lang": "en",
      |                "name": "Augustinas",
      |                "id_str": "819125281931792384",
      |                "entities": {
      |                    "description": {
      |                        "urls": []
      |                    }
      |                },
      |                "location": "",
      |                "verified": false,
      |                "following": false,
      |                "protected": true,
      |                "time_zone": null,
      |                "created_at": "Wed Jan 11 10:14:20 +0000 2017",
      |                "utc_offset": null,
      |                "description": "",
      |                "geo_enabled": false,
      |                "screen_name": "augustinas_test",
      |                "listed_count": 0,
      |                "friends_count": 28,
      |                "is_translator": false,
      |                "notifications": false,
      |                "statuses_count": 22,
      |                "default_profile": true,
      |                "followers_count": 0,
      |                "translator_type": "none",
      |                "favourites_count": 0,
      |                "profile_image_url": "http://abs.twimg.com/sticky/default_profile_images/default_profile_normal.png",
      |                "profile_link_color": "1DA1F2",
      |                "profile_text_color": "333333",
      |                "follow_request_sent": false,
      |                "contributors_enabled": false,
      |                "has_extended_profile": false,
      |                "default_profile_image": true,
      |                "is_translation_enabled": false,
      |                "profile_background_tile": false,
      |                "profile_image_url_https": "https://abs.twimg.com/sticky/default_profile_images/default_profile_normal.png",
      |                "profile_background_color": "F5F8FA",
      |                "profile_sidebar_fill_color": "DDEEF6",
      |                "profile_background_image_url": null,
      |                "profile_sidebar_border_color": "C0DEED",
      |                "profile_use_background_image": true,
      |                "profile_background_image_url_https": null
      |            },
      |            "place": null,
      |            "id_str": "953685879859679233",
      |            "source": "<a href=\"http://twitter.com\" rel=\"nofollow\">Twitter Web Client</a>",
      |            "entities": {
      |                "urls": [],
      |                "symbols": [],
      |                "hashtags": [],
      |                "user_mentions": []
      |            },
      |            "favorited": false,
      |            "retweeted": false,
      |            "truncated": false,
      |            "created_at": "Wed Jan 17 17:50:07 +0000 2018",
      |            "coordinates": null,
      |            "lastUpdated": "2018-01-17T17:50:07.000Z",
      |            "contributors": null,
      |            "retweet_count": 0,
      |            "favorite_count": 0,
      |            "is_quote_status": false,
      |            "in_reply_to_user_id": null,
      |            "in_reply_to_status_id": null,
      |            "in_reply_to_screen_name": null,
      |            "in_reply_to_user_id_str": null,
      |            "in_reply_to_status_id_str": null
      |        }
      |    }
    """.stripMargin

  val exampleTweetMinimalFields: EndpointData = Json.parse(exampleTweetMinimalFieldsText).as[EndpointData]

  private val exampleFacebookPhotoPostText =
    """
      |{
      |        "endpoint": "facebook/feed",
      |        "recordId": "597d28d5-19fe-4987-a986-0d7bb4b13a2b",
      |        "data": {
      |            "id": "10208242138349438_10214705870378699",
      |            "from": {
      |                "id": "10208242138349438",
      |                "name": "Andrius Aucinas"
      |            },
      |            "link": "https://www.facebook.com/photo.php?fbid=10214705869898687&set=a.1528612013548.2070101.1182147740&type=3",
      |            "type": "photo",
      |            "story": "Andrius Aucinas is in Cambridge, Cambridgeshire.",
      |            "message": "bat for self defence?",
      |            "picture": "https://scontent.xx.fbcdn.net/v/t1.0-0/s130x130/22853431_10214705869898687_7995276047144443863_n.jpg?oh=822b63617cc744bb2a1b2d5d586914be&oe=5AA3FC03",
      |            "privacy": {
      |                "deny": "2461771541953",
      |                "allow": "",
      |                "value": "CUSTOM",
      |                "friends": "ALL_FRIENDS",
      |                "description": "Friends"
      |            },
      |            "object_id": "10214705869898687",
      |            "lastUpdated": "2017-11-01T12:34:55+0000",
      |            "status_type": "added_photos",
      |            "created_time": "2017-11-01T10:18:34+0000",
      |            "full_picture": "https://scontent.xx.fbcdn.net/v/t1.0-9/s720x720/22853431_10214705869898687_7995276047144443863_n.jpg?oh=56c72e1de26992eb2af95fb8c2bc69bf&oe=5AA8D30E",
      |            "updated_time": "2017-11-01T11:55:42+0000"
      |        }
      |    }
    """.stripMargin

  val exampleFacebookPhotoPost: EndpointData = Json.parse(exampleFacebookPhotoPostText).as[EndpointData]

  private val exampleFacebookPostText =
    """
      |{
      |        "endpoint": "facebook/feed",
      |        "recordId": "fd863cdd-1585-47a2-ada7-9e5177ab1cba",
      |        "data": {
      |            "id": "10208242138349438_10214298168906417",
      |            "from": {
      |                "id": "10208242138349438",
      |                "name": "Andrius Aucinas"
      |            },
      |            "type": "status",
      |            "message": "jetlag wouldn't be so bad if not for  Aileen signing (whistling?) out the window overnight...",
      |            "privacy": {
      |                "deny": "2461771541953",
      |                "allow": "",
      |                "value": "CUSTOM",
      |                "friends": "ALL_FRIENDS",
      |                "description": "Friends"
      |            },
      |            "lastUpdated": "2017-11-01T12:34:55+0000",
      |            "status_type": "mobile_status_update",
      |            "created_time": "2017-09-13T07:46:36+0000",
      |            "updated_time": "2017-09-13T07:46:36+0000"
      |        }
      |    }
    """.stripMargin

  val exampleFacebookPost: EndpointData = Json.parse(exampleFacebookPostText).as[EndpointData]

  private val facebookStoryText =
    """
      |{
      |        "endpoint": "facebook/feed",
      |        "recordId": "303b8480-f801-46d5-a046-9a3fe96cdf53",
      |        "data": {
      |            "id": "10208242138349438_10214203256533667",
      |            "from": {
      |                "id": "10208242138349438",
      |                "name": "Andrius Aucinas"
      |            },
      |            "link": "http://phdcomics.com/comics.php?f=1969",
      |            "name": "PHD Comic: Ritual",
      |            "type": "link",
      |            "caption": "phdcomics.com",
      |            "message": "Guilty. Though works for startups too.",
      |            "picture": "https://external.xx.fbcdn.net/safe_image.php?d=AQBjCcxjSSET5Fd8&w=130&h=130&url=http%3A%2F%2Fphdcomics.com%2Fcomics%2Farchive%2Fphd082817s.gif&cfs=1&_nc_hash=AQCRgcZeWGHDqssI",
      |            "privacy": {
      |                "deny": "2461771541953",
      |                "allow": "",
      |                "value": "CUSTOM",
      |                "friends": "ALL_FRIENDS",
      |                "description": "Friends"
      |            },
      |            "description": "Link to Piled Higher and Deeper",
      |            "lastUpdated": "2017-11-01T12:34:55+0000",
      |            "status_type": "shared_story",
      |            "created_time": "2017-09-01T18:18:25+0000",
      |            "full_picture": "https://external.xx.fbcdn.net/safe_image.php?d=AQAA9b6_gghmCwA_&url=http%3A%2F%2Fphdcomics.com%2Fcomics%2Farchive%2Fphd082817s.gif&_nc_hash=AQA43U-PkGB246A8",
      |            "updated_time": "2017-09-01T18:18:25+0000"
      |        }
      |    }
    """.stripMargin

  val facebookStory: EndpointData = Json.parse(facebookStoryText).as[EndpointData]

  private val facebookEventText =
    """
      |{
      |        "endpoint": "facebook/events",
      |        "recordId": "a009dff1-a08a-4be7-9e5c-ec345ae25e83",
      |        "data": {
      |            "id": "956513997822293",
      |            "name": "MadHATTERS Singapore: Startups Change the Internet",
      |            "place": {
      |                "id": "137829469754469",
      |                "name": "Carlton Hotel Singapore",
      |                "location": {
      |                    "zip": "189558",
      |                    "city": "Singapore",
      |                    "street": "76 Bras Basah Road",
      |                    "country": "Singapore",
      |                    "latitude": "1.29592",
      |                    "longitude": "103.85247"
      |                }
      |            },
      |            "end_time": "2017-09-05T21:00:00+0800",
      |            "start_time": "2017-09-05T17:00:00+0800",
      |            "description": "We're going somewhere new. The future of the digital economy is not the gadgets we create or the algorithms we can come up with - these are the road. The destination is data.\n\nJoin the founders and the creators of the Hub of All Things private data technology on their tour of SE Asia, as they recruit for the HAT Innovation accelerator in London and Cambridge, UK and talk about their role bringing about equitability and privacy in the personal data economy. Prof. Irene Ng, creator of the HAT, will present the technology that will change the Internet, presenting use cases, apps, and technology ideas with her co-founder and Head of Engineering, Dr. Andrius Aucinas of HATDeX and the Cambridge Coding Academy. \n\nCalled by Sarah Gordon of the Financial Times the \"future of data control,\" Hub of All Things technology is a data framework for the modern Internet. They are 'private data accounts' that let individuals store personal information for themselves, giving app developers and startups the ability to build on top of dozens of streams of live, up-to-date information that's linked by the first-party - the user themselves. Chat with Professor Irene Ng, creator of the HAT and Chairman of the HAT Community Foundation to understand how and why user accounts of the next generation of services and apps on the Internet will soon be replaced.\n\nAgenda\n- KEYNOTE: Startups Change the Internet\nProf. Irene Ng\n-HAT Innovation and tomorrow's technologies: Ideas, Use Cases, Opportunities, and the future of the startup\nDr. Andrius Aucinas\n- Truly personal: how data meets reading in publishing startups and the news\n- Your data is yours: Startups, Innovation, and the Government\n\nJoin us. RSVP today.",
      |            "lastUpdated": "2017-11-01T12:34:57+0000",
      |            "rsvp_status": "attending"
      |        }
      |    }
    """.stripMargin

  val facebookEvent: EndpointData = Json.parse(facebookEventText).as[EndpointData]

  private val facebookEvenNoLocationText =
    """
      | {
      |        "endpoint": "facebook/events",
      |        "recordId": "0b27141f-948a-43b2-834e-78dddd2c931c",
      |        "data": {
      |            "id": "435839040089222",
      |            "name": "Personal Data: Freedom and Rights - SODP",
      |            "end_time": "2017-08-29T20:30:00+0100",
      |            "start_time": "2017-08-29T17:30:00+0100",
      |            "description": "Covering areas such as privacy, security, access rights, regulation, transaction costs and ownership, property rights, this session will be chaired by Prof. John Naughton. \n\nJohn Naughton was elected a Fellow of the College in 1992 and is now an Emeritus Fellow; he served as Vice-President from 2011-2015. By background a systems engineer with a strong interest in the social impacts of networking technology, he has written a weekly column for the Observer since 1987. He has written extensively on technology and its role in society, is the author of a well-known history of the Internet – A Brief History of the Future (Phoenix, 2000) – and is currently working on changes in our information ecosystem brought about by technological change. His latest book – From Gutenberg to Zuckerberg: what you really need to know about the Internet – is published by Quercus Books. He was the Academic Advisor to the Arcadia Project at Cambridge University Library, which ran from 2008-2012 and investigated the role of the academic library in a digital age. He is currently a Senior Research Fellow in the Centre for Research in the Arts, Social Sciences and Humanities (CRASSH) where (with Professor Richard Evans and Professor David Runciman) he is a Principal Investigator on the Leverhulme-funded research project on “Conspiracy and Democracy”.",
      |            "lastUpdated": "2017-11-01T12:34:57+0000",
      |            "rsvp_status": "attending"
      |        }
      |    }
    """.stripMargin

  val facebookEvenNoLocation: EndpointData = Json.parse(facebookEvenNoLocationText).as[EndpointData]

  private val facebookEvenPartialLocationText =
    """
      | {
      |        "endpoint": "facebook/events",
      |        "recordId": "0b27141f-948a-43b2-834e-78dddd2c931c",
      |        "data": {
      |            "id": "435839040089222",
      |            "name": "Personal Data: Freedom and Rights - SODP",
      |            "place": {
      |              "name": "8 Aylestone road, Cambridge, cb4 1hf"
      |            },
      |            "end_time": "2017-08-29T20:30:00+0100",
      |            "start_time": "2017-08-29T17:30:00+0100",
      |            "description": "Copy of Covering areas such as privacy, security, access rights, regulation, transaction costs and ownership, property rights, this session will be chaired by Prof. John Naughton. \n\nJohn Naughton was elected a Fellow of the College in 1992 and is now an Emeritus Fellow; he served as Vice-President from 2011-2015. By background a systems engineer with a strong interest in the social impacts of networking technology, he has written a weekly column for the Observer since 1987. He has written extensively on technology and its role in society, is the author of a well-known history of the Internet – A Brief History of the Future (Phoenix, 2000) – and is currently working on changes in our information ecosystem brought about by technological change. His latest book – From Gutenberg to Zuckerberg: what you really need to know about the Internet – is published by Quercus Books. He was the Academic Advisor to the Arcadia Project at Cambridge University Library, which ran from 2008-2012 and investigated the role of the academic library in a digital age. He is currently a Senior Research Fellow in the Centre for Research in the Arts, Social Sciences and Humanities (CRASSH) where (with Professor Richard Evans and Professor David Runciman) he is a Principal Investigator on the Leverhulme-funded research project on “Conspiracy and Democracy”.",
      |            "lastUpdated": "2017-11-01T12:34:57+0000",
      |            "rsvp_status": "attending"
      |        }
      |    }
    """.stripMargin

  val facebookEvenPartialLocation: EndpointData = Json.parse(facebookEvenPartialLocationText).as[EndpointData]

  private val fitbitWeightMeasurementText =
    """
      |{
      |        "endpoint": "fitbit/weight",
      |        "recordId": "1cdb94e5-b0df-4837-9d10-93a9c7d6475c",
      |        "data": {
      |            "bmi": 25.46,
      |            "fat": 21.545000076293945,
      |            "date": "2017-10-23",
      |            "time": "07:04:37",
      |            "logId": 1508742277000,
      |            "source": "Aria",
      |            "weight": 94.8
      |        }
      |    }
    """.stripMargin

  val fitbitWeightMeasurement: EndpointData = Json.parse(fitbitWeightMeasurementText).as[EndpointData]

  private val fitbitSleepMeasurementText =
    """
      | {
      |        "endpoint": "fitbit/sleep",
      |        "recordId": "a2ac4769-9c2e-4968-a91b-3c026e8d759d",
      |        "data": {
      |            "type": "classic",
      |            "logId": 14217883037,
      |            "levels": {
      |                "data": [
      |                    {
      |                        "level": "restless",
      |                        "seconds": 120,
      |                        "dateTime": "2017-08-30T00:15:00.000"
      |                    },
      |                    {
      |                        "level": "asleep",
      |                        "seconds": 60,
      |                        "dateTime": "2017-08-30T00:17:00.000"
      |                    },
      |                    {
      |                        "level": "restless",
      |                        "seconds": 60,
      |                        "dateTime": "2017-08-30T00:18:00.000"
      |                    },
      |                    {
      |                        "level": "asleep",
      |                        "seconds": 120,
      |                        "dateTime": "2017-08-30T00:19:00.000"
      |                    },
      |                    {
      |                        "level": "restless",
      |                        "seconds": 180,
      |                        "dateTime": "2017-08-30T00:21:00.000"
      |                    },
      |                    {
      |                        "level": "asleep",
      |                        "seconds": 1980,
      |                        "dateTime": "2017-08-30T00:24:00.000"
      |                    },
      |                    {
      |                        "level": "restless",
      |                        "seconds": 120,
      |                        "dateTime": "2017-08-30T00:57:00.000"
      |                    },
      |                    {
      |                        "level": "asleep",
      |                        "seconds": 120,
      |                        "dateTime": "2017-08-30T00:59:00.000"
      |                    },
      |                    {
      |                        "level": "restless",
      |                        "seconds": 60,
      |                        "dateTime": "2017-08-30T01:01:00.000"
      |                    },
      |                    {
      |                        "level": "asleep",
      |                        "seconds": 780,
      |                        "dateTime": "2017-08-30T01:02:00.000"
      |                    },
      |                    {
      |                        "level": "restless",
      |                        "seconds": 180,
      |                        "dateTime": "2017-08-30T01:15:00.000"
      |                    },
      |                    {
      |                        "level": "asleep",
      |                        "seconds": 6660,
      |                        "dateTime": "2017-08-30T01:18:00.000"
      |                    },
      |                    {
      |                        "level": "restless",
      |                        "seconds": 120,
      |                        "dateTime": "2017-08-30T03:09:00.000"
      |                    },
      |                    {
      |                        "level": "asleep",
      |                        "seconds": 120,
      |                        "dateTime": "2017-08-30T03:11:00.000"
      |                    },
      |                    {
      |                        "level": "restless",
      |                        "seconds": 60,
      |                        "dateTime": "2017-08-30T03:13:00.000"
      |                    },
      |                    {
      |                        "level": "asleep",
      |                        "seconds": 2640,
      |                        "dateTime": "2017-08-30T03:14:00.000"
      |                    },
      |                    {
      |                        "level": "restless",
      |                        "seconds": 120,
      |                        "dateTime": "2017-08-30T03:58:00.000"
      |                    },
      |                    {
      |                        "level": "asleep",
      |                        "seconds": 120,
      |                        "dateTime": "2017-08-30T04:00:00.000"
      |                    },
      |                    {
      |                        "level": "restless",
      |                        "seconds": 60,
      |                        "dateTime": "2017-08-30T04:02:00.000"
      |                    },
      |                    {
      |                        "level": "asleep",
      |                        "seconds": 1380,
      |                        "dateTime": "2017-08-30T04:03:00.000"
      |                    },
      |                    {
      |                        "level": "restless",
      |                        "seconds": 240,
      |                        "dateTime": "2017-08-30T04:26:00.000"
      |                    },
      |                    {
      |                        "level": "asleep",
      |                        "seconds": 4740,
      |                        "dateTime": "2017-08-30T04:30:00.000"
      |                    },
      |                    {
      |                        "level": "restless",
      |                        "seconds": 120,
      |                        "dateTime": "2017-08-30T05:49:00.000"
      |                    },
      |                    {
      |                        "level": "asleep",
      |                        "seconds": 120,
      |                        "dateTime": "2017-08-30T05:51:00.000"
      |                    },
      |                    {
      |                        "level": "restless",
      |                        "seconds": 60,
      |                        "dateTime": "2017-08-30T05:53:00.000"
      |                    },
      |                    {
      |                        "level": "asleep",
      |                        "seconds": 120,
      |                        "dateTime": "2017-08-30T05:54:00.000"
      |                    },
      |                    {
      |                        "level": "restless",
      |                        "seconds": 120,
      |                        "dateTime": "2017-08-30T05:56:00.000"
      |                    },
      |                    {
      |                        "level": "asleep",
      |                        "seconds": 60,
      |                        "dateTime": "2017-08-30T05:58:00.000"
      |                    },
      |                    {
      |                        "level": "restless",
      |                        "seconds": 120,
      |                        "dateTime": "2017-08-30T05:59:00.000"
      |                    },
      |                    {
      |                        "level": "asleep",
      |                        "seconds": 240,
      |                        "dateTime": "2017-08-30T06:01:00.000"
      |                    },
      |                    {
      |                        "level": "restless",
      |                        "seconds": 120,
      |                        "dateTime": "2017-08-30T06:05:00.000"
      |                    },
      |                    {
      |                        "level": "asleep",
      |                        "seconds": 1500,
      |                        "dateTime": "2017-08-30T06:07:00.000"
      |                    },
      |                    {
      |                        "level": "restless",
      |                        "seconds": 60,
      |                        "dateTime": "2017-08-30T06:32:00.000"
      |                    },
      |                    {
      |                        "level": "asleep",
      |                        "seconds": 1620,
      |                        "dateTime": "2017-08-30T06:33:00.000"
      |                    },
      |                    {
      |                        "level": "restless",
      |                        "seconds": 120,
      |                        "dateTime": "2017-08-30T07:00:00.000"
      |                    },
      |                    {
      |                        "level": "asleep",
      |                        "seconds": 1380,
      |                        "dateTime": "2017-08-30T07:02:00.000"
      |                    },
      |                    {
      |                        "level": "restless",
      |                        "seconds": 120,
      |                        "dateTime": "2017-08-30T07:25:00.000"
      |                    },
      |                    {
      |                        "level": "asleep",
      |                        "seconds": 1200,
      |                        "dateTime": "2017-08-30T07:27:00.000"
      |                    },
      |                    {
      |                        "level": "restless",
      |                        "seconds": 180,
      |                        "dateTime": "2017-08-30T07:47:00.000"
      |                    },
      |                    {
      |                        "level": "asleep",
      |                        "seconds": 180,
      |                        "dateTime": "2017-08-30T07:50:00.000"
      |                    },
      |                    {
      |                        "level": "restless",
      |                        "seconds": 60,
      |                        "dateTime": "2017-08-30T07:53:00.000"
      |                    },
      |                    {
      |                        "level": "asleep",
      |                        "seconds": 360,
      |                        "dateTime": "2017-08-30T07:54:00.000"
      |                    },
      |                    {
      |                        "level": "restless",
      |                        "seconds": 120,
      |                        "dateTime": "2017-08-30T08:00:00.000"
      |                    },
      |                    {
      |                        "level": "asleep",
      |                        "seconds": 780,
      |                        "dateTime": "2017-08-30T08:02:00.000"
      |                    },
      |                    {
      |                        "level": "restless",
      |                        "seconds": 120,
      |                        "dateTime": "2017-08-30T08:15:00.000"
      |                    },
      |                    {
      |                        "level": "asleep",
      |                        "seconds": 120,
      |                        "dateTime": "2017-08-30T08:17:00.000"
      |                    }
      |                ],
      |                "summary": {
      |                    "awake": {
      |                        "count": 0,
      |                        "minutes": 0
      |                    },
      |                    "asleep": {
      |                        "count": 0,
      |                        "minutes": 440
      |                    },
      |                    "restless": {
      |                        "count": 23,
      |                        "minutes": 44
      |                    }
      |                }
      |            },
      |            "endTime": "2017-08-30T08:19:30.000",
      |            "duration": 29040000,
      |            "infoCode": 0,
      |            "startTime": "2017-08-30T00:15:00.000",
      |            "timeInBed": 484,
      |            "efficiency": 91,
      |            "dateOfSleep": "2017-08-30",
      |            "minutesAwake": 44,
      |            "minutesAsleep": 440,
      |            "minutesAfterWakeup": 0,
      |            "minutesToFallAsleep": 0
      |        }
      |    }
    """.stripMargin

  val fitbitSleepMeasurement: EndpointData = Json.parse(fitbitSleepMeasurementText).as[EndpointData]

  private val fitbitActivityText =
    """
      | {
      |        "endpoint": "fitbit/activity",
      |        "recordId": "d85c4b7e-937c-4e72-a58a-f4335f916e41",
      |        "data": {
      |            "logId": 5590585922,
      |            "steps": 1257,
      |            "logType": "auto_detected",
      |            "calories": 126,
      |            "duration": 1023000,
      |            "startTime": "2017-08-15T16:19:23.000Z",
      |            "activityName": "Walk",
      |            "lastModified": "2017-08-15T16:39:47.000Z",
      |            "activityLevel": [
      |                {
      |                    "name": "sedentary",
      |                    "minutes": 1
      |                },
      |                {
      |                    "name": "lightly",
      |                    "minutes": 16
      |                },
      |                {
      |                    "name": "fairly",
      |                    "minutes": 0
      |                },
      |                {
      |                    "name": "very",
      |                    "minutes": 0
      |                }
      |            ],
      |            "elevationGain": 9.144,
      |            "activeDuration": 1023000,
      |            "activityTypeId": 90013,
      |            "heartRateZones": [
      |                {
      |                    "max": 96,
      |                    "min": 30,
      |                    "name": "Out of Range",
      |                    "minutes": 8
      |                },
      |                {
      |                    "max": 135,
      |                    "min": 96,
      |                    "name": "Fat Burn",
      |                    "minutes": 9
      |                },
      |                {
      |                    "max": 164,
      |                    "min": 135,
      |                    "name": "Cardio",
      |                    "minutes": 0
      |                },
      |                {
      |                    "max": 220,
      |                    "min": 164,
      |                    "name": "Peak",
      |                    "minutes": 0
      |                }
      |            ],
      |            "averageHeartRate": 94,
      |            "originalDuration": 1023000,
      |            "originalStartTime": "2017-08-15T16:19:23.000Z",
      |            "manualValuesSpecified": {
      |                "steps": false,
      |                "calories": false,
      |                "distance": false
      |            }
      |        }
      |    }
    """.stripMargin

  val fitbitActivity: EndpointData = Json.parse(fitbitActivityText).as[EndpointData]

  private val fitbitDaySummaryText =
    """
      | {
      |        "endpoint": "fitbit/activity/day/summary",
      |        "recordId": "b4b9f6df-9fd9-41cf-8999-98bd3b7a1831",
      |        "data": {
      |            "steps": 12135,
      |            "floors": 0,
      |            "distances": [
      |                {
      |                    "activity": "total",
      |                    "distance": 0
      |                },
      |                {
      |                    "activity": "tracker",
      |                    "distance": 0
      |                },
      |                {
      |                    "activity": "loggedActivities",
      |                    "distance": 0
      |                },
      |                {
      |                    "activity": "veryActive",
      |                    "distance": 0
      |                },
      |                {
      |                    "activity": "moderatelyActive",
      |                    "distance": 0
      |                },
      |                {
      |                    "activity": "lightlyActive",
      |                    "distance": 0
      |                },
      |                {
      |                    "activity": "sedentaryActive",
      |                    "distance": 0
      |                }
      |            ],
      |            "elevation": 0,
      |            "activeScore": -1,
      |            "caloriesBMR": 2035,
      |            "caloriesOut": 2035,
      |            "dateCreated": "2017-11-03",
      |            "activityCalories": 0,
      |            "marginalCalories": 0,
      |            "sedentaryMinutes": 1440,
      |            "veryActiveMinutes": 0,
      |            "fairlyActiveMinutes": 0,
      |            "lightlyActiveMinutes": 0
      |        }
      |    }
    """.stripMargin

  val fitbitDaySummary: EndpointData = Json.parse(fitbitDaySummaryText).as[EndpointData]

  private val fitbitDayEmptySummaryText =
    """
      | {
      |        "endpoint": "fitbit/activity/day/summary",
      |        "recordId": "b4b9f6df-9fd9-41cf-8999-98bd3b7a1831",
      |        "data": {
      |            "steps": 0,
      |            "floors": 0,
      |            "distances": [
      |                {
      |                    "activity": "total",
      |                    "distance": 0
      |                },
      |                {
      |                    "activity": "tracker",
      |                    "distance": 0
      |                },
      |                {
      |                    "activity": "loggedActivities",
      |                    "distance": 0
      |                },
      |                {
      |                    "activity": "veryActive",
      |                    "distance": 0
      |                },
      |                {
      |                    "activity": "moderatelyActive",
      |                    "distance": 0
      |                },
      |                {
      |                    "activity": "lightlyActive",
      |                    "distance": 0
      |                },
      |                {
      |                    "activity": "sedentaryActive",
      |                    "distance": 0
      |                }
      |            ],
      |            "elevation": 0,
      |            "activeScore": -1,
      |            "caloriesBMR": 2035,
      |            "caloriesOut": 2035,
      |            "dateCreated": "2017-11-03",
      |            "activityCalories": 0,
      |            "marginalCalories": 0,
      |            "sedentaryMinutes": 1440,
      |            "veryActiveMinutes": 0,
      |            "fairlyActiveMinutes": 0,
      |            "lightlyActiveMinutes": 0
      |        }
      |    }
    """.stripMargin

  val fitbitDayEmptySummary: EndpointData = Json.parse(fitbitDayEmptySummaryText).as[EndpointData]

  private val googleCalendaEventText =
    """
      |{
      |        "endpoint": "calendar/google/events",
      |        "recordId": "bff0fbbd-78af-4999-a1fa-f7e70864d85b",
      |        "data": {
      |            "id": "1084m8261rnnk0g5k5en7da63u",
      |            "end": {
      |                "dateTime": "2017-12-13T03:30:00Z",
      |                "timeZone": "America/New_York"
      |            },
      |            "etag": "\"3019071330104000\"",
      |            "kind": "calendar#event",
      |            "start": {
      |                "dateTime": "2017-12-12T23:30:00Z",
      |                "timeZone": "America/New_York"
      |            },
      |            "status": "confirmed",
      |            "created": "2017-11-01T11:26:05.000Z",
      |            "creator": {
      |                "email": "holtby.jonathan@gmail.com",
      |                "displayName": "Jonathan Holtby"
      |            },
      |            "iCalUID": "1084m8261rnnk0g5k5en7da63u@google.com",
      |            "summary": "MadHATTERs Tea Party: The Boston Party",
      |            "updated": "2017-11-01T11:27:45.052Z",
      |            "htmlLink": "https://www.google.com/calendar/event?eid=MTA4NG04MjYxcm5uazBnNWs1ZW43ZGE2M3UgZjRsZHZqbDd0a3RvZjBtcGVqZjQxMTU0Y3NAZw",
      |            "location": "Boston, MA, USA",
      |            "sequence": 1,
      |            "organizer": {
      |                "self": true,
      |                "email": "f4ldvjl7tktof0mpejf41154cs@group.calendar.google.com",
      |                "displayName": "HAT Platform"
      |            },
      |            "reminders": {
      |                "useDefault": true
      |            },
      |            "calendarId": "f4ldvjl7tktof0mpejf41154cs@group.calendar.google.com",
      |            "description": "Join Prof. Irene Ng from the Hub of All Things and the Universities of Warwick and Cambridge to talk about users - their personal data, user accounts, security and value.\n\nTHE GREAT AND GLORIOUS USER: WHO OWNS THEM, WHO PROTECTS THEM, AND WHAT THEY'RE WORTH\n\nIn the first half of this century, the growth of the digital self has been explosive. Since at least the mid 2000's, the increasing ubiquity of tech has made our digital lives ever more prevalent, relevant, and valuable. We are no longer Internet users, we're Internet citizens. But the garbage representations of ourselves that we enjoy online are increasingly a source of focus.\n\nBecause of the fragmented, gross insufficiency of data, personalisation is a cruel parody of what it would need to be to deliver maximum value. Advertising intrudes, to the extent where even when it works it annoys, and the reality of privacy today has become a fiction. We are lucky if our most trusted services only use our most personal information for good - not using it at all has gone completely off the table.\n\nThe digital economy that reaps of this reality does not have to be dystopian. There is infinitely more wealth in the personal data of the future than there is heartache and pain. But to realise it we need to begin to ask ourselves: Who owns the user? Do they own themselves? Or do we own them? And why?\n\nJoin the Hub of All Things, a data privacy and empowerment technology, for a discussion on the future of the digital economy, and explore with us the opportunity and worth of a personal data economy that holds the empowered individual at its core. December 12, 2017 in Boston, 6:30 - 10:30pm Eastern.\n\nABOUT THE SPEAKER\nProf. Irene Ng is a Director at the University of Warwick, a Fellow at Wolfson College, Cambridge, and the Creator of the Hub of All Things Private Data Account. Irene is a Mentor and Economic Advisor to numerous Enterprises and Startups and a champion of the personal data economy (coming soon to an Internet vertical near you).\n\nABOUT THE HAT\nHAT Technology is a private data account that stores and exchanges individually-controlled personal data on behalf of its owners. Learn more about it and its promise at www.hubofallthings.com"
      |        }
      |      }
    """.stripMargin

  val googleCalendarEvent: EndpointData = Json.parse(googleCalendaEventText).as[EndpointData]

  private val googleCalendaEventHtmlText =
    """
      |{
      |        "endpoint": "calendar/google/events",
      |        "recordId": "bff0fbbd-78af-4999-a1fa-f7e70864d85b",
      |        "data": {
      |            "id": "1084m8261rnnk0g5k5en7da63u",
      |            "end": {
      |                "dateTime": "2017-12-13T03:30:00Z",
      |                "timeZone": "America/New_York"
      |            },
      |            "etag": "\"3019071330104000\"",
      |            "kind": "calendar#event",
      |            "start": {
      |                "dateTime": "2017-12-12T23:30:00Z",
      |                "timeZone": "America/New_York"
      |            },
      |            "status": "confirmed",
      |            "created": "2017-11-01T11:26:05.000Z",
      |            "creator": {
      |                "email": "holtby.jonathan@gmail.com",
      |                "displayName": "Jonathan Holtby"
      |            },
      |            "iCalUID": "1084m8261rnnk0g5k5en7da63u@google.com",
      |            "summary": "MadHATTERs Tea Party: The Boston Party",
      |            "updated": "2017-11-01T11:27:45.052Z",
      |            "htmlLink": "https://www.google.com/calendar/event?eid=MTA4NG04MjYxcm5uazBnNWs1ZW43ZGE2M3UgZjRsZHZqbDd0a3RvZjBtcGVqZjQxMTU0Y3NAZw",
      |            "location": "Boston, MA, USA",
      |            "sequence": 1,
      |            "organizer": {
      |                "self": true,
      |                "email": "f4ldvjl7tktof0mpejf41154cs@group.calendar.google.com",
      |                "displayName": "HAT Platform"
      |            },
      |            "reminders": {
      |                "useDefault": true
      |            },
      |            "calendarId": "f4ldvjl7tktof0mpejf41154cs@group.calendar.google.com",
      |            "description": "BD call&nbsp;<br><br>Please join my meeting from your computer, tablet or smartphone.&nbsp;<br><a href=\"https://global.gotomeeting.com/join/00000000\" target=\"_blank\">https://global.gotomeeting.com/join/00000000&nbsp;</a><br><br>You can also dial in using your phone.&nbsp;<br>United Kingdom: +44 20 3713 5028&nbsp;<br><br>Access Code:&nbsp;000-000-000&nbsp;<br><br>More phone numbers&nbsp;<br>United States: +1 (571) 317-3129&nbsp;<br>Canada: +1 (647) 497-9391&nbsp;<br><br>First GoToMeeting? Let's do a quick system check:<a href=\"https://link.gotomeeting.com/system-check\" target=\"_blank\">https://link.gotomeeting.com/system-check</a>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"
      |        }
      |      }
    """.stripMargin

  val googleCalendarEventHtml: EndpointData = Json.parse(googleCalendaEventHtmlText).as[EndpointData]

  private val googleCalendarFullDayEventText =
    """
      | {
      |        "endpoint": "calendar/google/events",
      |        "recordId": "ab1c1d08-0a17-49bc-acaf-ddc71a05fc3e",
      |        "data": {
      |            "id": "_611jichm84r44ba36co3eb9k8d2j4b9p6go30ba26spjge1m6spk8ga260",
      |            "end": {
      |                "date": "2017-10-30"
      |            },
      |            "etag": "\"3015003741261000\"",
      |            "kind": "calendar#event",
      |            "start": {
      |                "date": "2017-10-27"
      |            },
      |            "status": "confirmed",
      |            "created": "2017-09-21T12:56:37.000Z",
      |            "creator": {
      |                "email": "andrius.aucinas@gmail.com",
      |                "displayName": "Andrius Aučinas"
      |            },
      |            "iCalUID": "0C926A6B-C307-4CE2-9400-B7388673DAB0",
      |            "summary": "MozFest",
      |            "updated": "2017-10-26T08:05:43.918Z",
      |            "htmlLink": "https://www.google.com/calendar/event?eid=XzYxMWppY2htODRyNDRiYTM2Y28zZWI5azhkMmo0YjlwNmdvMzBiYTI2c3BqZ2UxbTZzcGs4Z2EyNjAgZjRsZHZqbDd0a3RvZjBtcGVqZjQxMTU0Y3NAZw",
      |            "sequence": 0,
      |            "organizer": {
      |                "self": true,
      |                "email": "f4ldvjl7tktof0mpejf41154cs@group.calendar.google.com",
      |                "displayName": "HAT Platform"
      |            },
      |            "reminders": {
      |                "useDefault": false
      |            },
      |            "calendarId": "f4ldvjl7tktof0mpejf41154cs@group.calendar.google.com",
      |            "transparency": "transparent"
      |        }
      |    }
    """.stripMargin

  val googleCalendarFullDayEvent: EndpointData = Json.parse(googleCalendarFullDayEventText).as[EndpointData]

  private val instagramImagePostv1 =
    """
      |{
      |        "endpoint": "instagram/feed",
      |        "recordId": "2ab1ba13-1f52-4340-b5d6-6cb99bc2b8f1",
      |        "data": {
      |            "id": "1772411616076286885_239605641",
      |            "link": "https://www.instagram.com/p/BiY3vlkAMul/",
      |            "tags": [
      |                "goodmorning",
      |                "saturday",
      |                "healthyfood"
      |            ],
      |            "type": "image",
      |            "user": {
      |                "id": "239605641",
      |                "username": "thetallfoodmaker",
      |                "full_name": "Gus Marke",
      |                "profile_picture": "https://scontent.cdninstagram.com/vp/f6c87f56dbf4bee40c6433113db61ac6/5BABD075/t51.2885-19/s150x150/22794237_238331963364835_6773830520112414720_n.jpg"
      |            },
      |            "likes": {
      |                "count": 6
      |            },
      |            "filter": "Juno",
      |            "images": {
      |                "thumbnail": {
      |                    "url": "https://scontent.cdninstagram.com/vp/fe1112fbf722cc7e0c9d7c24a4614d79/5BC3EA61/t51.2885-15/s150x150/e35/31168755_584427071935823_5068176866590851072_n.jpg",
      |                    "width": 150,
      |                    "height": 150
      |                },
      |                "low_resolution": {
      |                    "url": "https://scontent.cdninstagram.com/vp/5eed293c762c178710761ba2f839bcad/5BA89426/t51.2885-15/s320x320/e35/31168755_584427071935823_5068176866590851072_n.jpg",
      |                    "width": 320,
      |                    "height": 320
      |                },
      |                "standard_resolution": {
      |                    "url": "https://scontent.cdninstagram.com/vp/1012761e9acf47e0dc95a793b904c3ba/5BAF6465/t51.2885-15/s640x640/sh0.08/e35/31168755_584427071935823_5068176866590851072_n.jpg",
      |                    "width": 640,
      |                    "height": 640
      |                }
      |            },
      |            "caption": {
      |                "id": "17881349008217653",
      |                "from": {
      |                    "id": "239605641",
      |                    "username": "thetallfoodmaker",
      |                    "full_name": "Gus Marke",
      |                    "profile_picture": "https://scontent.cdninstagram.com/vp/f6c87f56dbf4bee40c6433113db61ac6/5BABD075/t51.2885-19/s150x150/22794237_238331963364835_6773830520112414720_n.jpg"
      |                },
      |                "text": "Saturday breakfast magic. Made with quinoa, strawberries, blueberries, açai and tad bit of honey.  #healthyfood #goodmorning #saturday",
      |                "created_time": "1525507951"
      |            },
      |            "comments": {
      |                "count": 0
      |            },
      |            "location": null,
      |            "attribution": null,
      |            "created_time": "1525507951",
      |            "user_has_liked": false,
      |            "users_in_photo": []
      |        }
      |    }
    """.stripMargin

  val exampleInstagramImagev1: EndpointData = Json.parse(instagramImagePostv1).as[EndpointData]

  private val instagramMultipleImagePost =
    """
      |{
      |        "endpoint": "instagram/feed",
      |        "recordId": "83e82952-cc3c-44b8-9127-405671bc37cb",
      |        "data": {
      |            "id": "1636442711489664731_239605641",
      |            "link": "https://www.instagram.com/p/Ba1z_nRnlbb/",
      |            "tags": [
      |                "london",
      |                "nature",
      |                "wildlife",
      |                "active",
      |                "richmond",
      |                "stayactive",
      |                "sundaywalk",
      |                "happyday"
      |            ],
      |            "type": "carousel",
      |            "user": {
      |                "id": "239605641",
      |                "username": "thetallfoodmaker",
      |                "full_name": "Gus Marke",
      |                "profile_picture": "https://scontent.cdninstagram.com/vp/f6c87f56dbf4bee40c6433113db61ac6/5BABD075/t51.2885-19/s150x150/22794237_238331963364835_6773830520112414720_n.jpg"
      |            },
      |            "likes": {
      |                "count": 7
      |            },
      |            "filter": "Normal",
      |            "images": {
      |                "thumbnail": {
      |                    "url": "https://scontent.cdninstagram.com/vp/842f47bf6577fb0a86a4107bec37de37/5BA18E77/t51.2885-15/s150x150/e35/23101195_391308361303260_9190986119427129344_n.jpg",
      |                    "width": 150,
      |                    "height": 150
      |                },
      |                "low_resolution": {
      |                    "url": "https://scontent.cdninstagram.com/vp/219747f95097fd95bf80b2b5cac02de8/5BAAEE30/t51.2885-15/s320x320/e35/23101195_391308361303260_9190986119427129344_n.jpg",
      |                    "width": 320,
      |                    "height": 320
      |                },
      |                "standard_resolution": {
      |                    "url": "https://scontent.cdninstagram.com/vp/ce03d9c34ceb42cca7d2d27940d31b9c/5BA46973/t51.2885-15/s640x640/sh0.08/e35/23101195_391308361303260_9190986119427129344_n.jpg",
      |                    "width": 640,
      |                    "height": 640
      |                }
      |            },
      |            "caption": {
      |                "id": "17879428666148826",
      |                "from": {
      |                    "id": "239605641",
      |                    "username": "thetallfoodmaker",
      |                    "full_name": "Gus Marke",
      |                    "profile_picture": "https://scontent.cdninstagram.com/vp/f6c87f56dbf4bee40c6433113db61ac6/5BABD075/t51.2885-19/s150x150/22794237_238331963364835_6773830520112414720_n.jpg"
      |                },
      |                "text": "The beauty of Richmond park... Have to be there to experience it.\n.\n#london #richmond #nature #wildlife #sundaywalk #happyday #active #stayactive",
      |                "created_time": "1509299194"
      |            },
      |            "comments": {
      |                "count": 0
      |            },
      |            "location": null,
      |            "attribution": null,
      |            "created_time": "1509299194",
      |            "carousel_media": [
      |                {
      |                    "type": "image",
      |                    "images": {
      |                        "thumbnail": {
      |                            "url": "https://scontent.cdninstagram.com/vp/842f47bf6577fb0a86a4107bec37de37/5BA18E77/t51.2885-15/s150x150/e35/23101195_391308361303260_9190986119427129344_n.jpg",
      |                            "width": 150,
      |                            "height": 150
      |                        },
      |                        "low_resolution": {
      |                            "url": "https://scontent.cdninstagram.com/vp/219747f95097fd95bf80b2b5cac02de8/5BAAEE30/t51.2885-15/s320x320/e35/23101195_391308361303260_9190986119427129344_n.jpg",
      |                            "width": 320,
      |                            "height": 320
      |                        },
      |                        "standard_resolution": {
      |                            "url": "https://scontent.cdninstagram.com/vp/ce03d9c34ceb42cca7d2d27940d31b9c/5BA46973/t51.2885-15/s640x640/sh0.08/e35/23101195_391308361303260_9190986119427129344_n.jpg",
      |                            "width": 640,
      |                            "height": 640
      |                        }
      |                    },
      |                    "users_in_photo": []
      |                },
      |                {
      |                    "type": "image",
      |                    "images": {
      |                        "thumbnail": {
      |                            "url": "https://scontent.cdninstagram.com/vp/6fd590bc431f0191b0a6dfdb248afbeb/5BC179AF/t51.2885-15/s150x150/e35/23098918_144561552831373_5461840495061762048_n.jpg",
      |                            "width": 150,
      |                            "height": 150
      |                        },
      |                        "low_resolution": {
      |                            "url": "https://scontent.cdninstagram.com/vp/e5e119054d8738038b7b0d747fe3729e/5BBDADE8/t51.2885-15/s320x320/e35/23098918_144561552831373_5461840495061762048_n.jpg",
      |                            "width": 320,
      |                            "height": 320
      |                        },
      |                        "standard_resolution": {
      |                            "url": "https://scontent.cdninstagram.com/vp/e84cef695046324811d0d930b348d97c/5BC338AB/t51.2885-15/s640x640/sh0.08/e35/23098918_144561552831373_5461840495061762048_n.jpg",
      |                            "width": 640,
      |                            "height": 640
      |                        }
      |                    },
      |                    "users_in_photo": []
      |                },
      |                {
      |                    "type": "image",
      |                    "images": {
      |                        "thumbnail": {
      |                            "url": "https://scontent.cdninstagram.com/vp/a0c9eda093058e546974db4376fbe28b/5BAC2472/t51.2885-15/s150x150/e35/22861138_887949221363887_2950919806850695168_n.jpg",
      |                            "width": 150,
      |                            "height": 150
      |                        },
      |                        "low_resolution": {
      |                            "url": "https://scontent.cdninstagram.com/vp/950932d341a67a4fa2580ae3a634d90f/5BB76B35/t51.2885-15/s320x320/e35/22861138_887949221363887_2950919806850695168_n.jpg",
      |                            "width": 320,
      |                            "height": 320
      |                        },
      |                        "standard_resolution": {
      |                            "url": "https://scontent.cdninstagram.com/vp/225a6154b4dd2efe2c1f1caf93095c7c/5BB26576/t51.2885-15/s640x640/sh0.08/e35/22861138_887949221363887_2950919806850695168_n.jpg",
      |                            "width": 640,
      |                            "height": 640
      |                        }
      |                    },
      |                    "users_in_photo": []
      |                }
      |            ],
      |            "user_has_liked": false,
      |            "users_in_photo": []
      |        }
      |    }
    """.stripMargin

  val exampleMultipleInstagramImages: EndpointData = Json.parse(instagramMultipleImagePost).as[EndpointData]

  private val instagramImagePostv2 =
    """
      |{
      |        "endpoint": "instagram/feed",
      |        "recordId": "2ab1ba13-1f52-4340-b5d6-6cb99bc2b8f1",
      |        "data": {
      |            "id": "17843502451208638",
      |            "caption": "Saturday breakfast magic",
      |            "username": "marios4th",
      |            "media_url": "https://scontent.xx.fbcdn.net/v/t51.2885-15/21827559_1735810643096299_7305270523276034048_n.jpg?_nc_cat=101&_nc_sid=8ae9d6&_nc_ohc=LEbATLws-CIAX9dGQKn&_nc_ht=scontent.xx&oh=e88cb14f8ffa2237a84b6f4eb3293527&oe=5E8BD928",
      |            "permalink": "https://www.instagram.com/p/BZ_Z-HFH4i-/",
      |            "timestamp": "2020-04-20T14:40:11+0000",
      |            "media_type": "IMAGE",
      |            "ds_api_version": "v2",
      |            "ds_created_time": "1588636800"
      |        }
      |    }
    """.stripMargin

  val exampleInstagramImagev2: EndpointData = Json.parse(instagramImagePostv2).as[EndpointData]
}

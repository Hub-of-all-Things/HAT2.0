package org.hatdex.hat.filters

import javax.inject.Inject

import com.github.stijndehaes.playprometheusfilters.filters.{ StatusAndRouteLatencyFilter, StatusCounterFilter }
import play.api.http.DefaultHttpFilters

class PrometheusFilters @Inject() (
    statusCounterFilter: StatusCounterFilter,
    statusAndRouteLatencyFilter: StatusAndRouteLatencyFilter)
    extends DefaultHttpFilters(statusCounterFilter, statusAndRouteLatencyFilter)

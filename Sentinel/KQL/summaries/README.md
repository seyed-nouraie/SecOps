## Want a full breakdown of these rules? Check out my free article here: https://modernsecops.com/p/microsoft-sentinel-summary-kql-deep-dive?utm_source=github&utm_medium=organic&utm_campaign=summary_kql
## Network IOCs  
```kql
let DestinationSummary = _ASim_NetworkSession()
    | summarize
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated),
        UniqueSources = dcount(SrcIpAddr),
        SrcPorts = dcount(SrcPortNumber),
        DstPorts = dcount(DstPortNumber),
        SrcByte = sum(SrcBytes),
        DstByte = sum(DstBytes),
        // Cannot use count, each row != one event
        EventCount = sum(EventCount)
        by IpAddr = DstIpAddr, NetworkDirection, DvcAction 
    // Need to identify if IP is src or dest
    | extend type = "Dst";
let SourceSummary = _ASim_NetworkSession()
    | summarize
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated),
        UniqueDestinations = dcount(DstIpAddr),
        SrcPorts = dcount(SrcPortNumber),
        DstPorts = dcount(DstPortNumber),
        SrcByte = sum(SrcBytes),
        DstByte = sum(DstBytes),
        EventCount=  sum(EventCount)
        by IpAddr = SrcIpAddr, NetworkDirection, DvcAction
    | extend type = "Src";
SourceSummary
| union DestinationSummary
```

## Auth Attacks  
```kql
let LowerPercentile = 5;
let MiddlePercentile = 50;
let HigherPercentile = 95;
let UserAgentSample = 5;
let GeoSample = 5;
_ASim_Authentication()
| sort by TimeGenerated asc
| extend
    EventDuration = datetime_diff('millisecond', EventStartTime, EventEndTime),
    TimeDelta = datetime_diff('second', next(EventStartTime), EventEndTime),
    Src = coalesce(Src, SrcIpAddr)
| extend Region = coalesce(SrcGeoRegion, SrcGeoCountry)
| summarize
    FirstSeen = min(EventStartTime),
    LastSeen = max(EventEndTime),
    TargetUsers = dcount(TargetUserId),
    TargetApps = dcount(TargetAppId),
    UserAgents = dcount(HttpUserAgent),
    UserAgentSet = make_set(HttpUserAgent, UserAgentSample),
    Geos = dcount(Region),
    GeoSet = make_set(Region, GeoSample),
    DeltaStdev = stdev(TimeDelta),
    DeltaPercentiles = percentiles_array(TimeDelta, LowerPercentile, MiddlePercentile, HigherPercentile),
    DeltaVariance = variance(TimeDelta),
    DeltaAvg = avg(TimeDelta),
    DeltaMin = min(TimeDelta),
    DeltaMax = max(TimeDelta)
    by Src, EventResultDetails, EventSubType
```

## Web attacks  
```kql
let LowerPercentile = 5;
let MiddlePercentile = 50;
let HigherPercentile = 95;
_ASim_WebSession()
| sort by EventStartTime asc
| extend
    EventDuration = datetime_diff('millisecond', EventStartTime, EventEndTime),
    Similarity = iif(isnotempty(next(Url)), jaccard_index(to_utf8(next(Url)), to_utf8(Url)), real(null))
| summarize
    FirstSeen = min(EventStartTime),
    LastSeen = max(EventEndTime),
    UrlsVisited = dcount(Url),
    EventCount = sum(EventCount),
    AvgDuration = avgif(EventDuration, EventDuration != 0),
    PercentilesDuration = percentiles_array(EventDuration, LowerPercentile, MiddlePercentile, HigherPercentile),
    SimilarityMin = min(Similarity),
    SimilarityMax = max(Similarity),
    SimilarityAvg = avg(Similarity)
    by SrcIpAddr, EventResultDetails, DvcAction
```

## Want more rules? Check out my colleague's awesome repo: https://github.com/Cyberlorians/Articles/blob/main/MaliciousActivityandSentinelP5.md

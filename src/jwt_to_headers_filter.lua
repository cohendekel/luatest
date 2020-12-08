local rolesinheaders =  {}


function rolesinheaders.array_to_string(table)
    result=""
    for i,v in ipairs(table) do
        if i == 1 then
            result=v
        else
            result=result..","..v
        end
    end
    return result
end

function rolesinheaders.putrolesinheaders(request_handle)
    print("debug - envoyfilter envoy_on_request")
    metadata = request_handle:streamInfo():dynamicMetadata():get("envoy.filters.http.jwt_authn")

    if metadata then
        claims=metadata["https://segasec-int.eu.auth0.com/"]

        local remote_headers, remote_body = request_handle:httpCall(
            "myservice",
            {
                [":method"] = "GET",
                [":path"] = "/status/200",
                [":authority"] = "myservice"
            },
            "",
            5000
        )

        for key,value in pairs(claims) do
            if (key == "https://segasec.com/user_authorization") then
                -- Simulate append groups based on remote response
                if remote_headers[":status"] == "200" then
                    fake_group="888"
                    groups=array_to_string(value["groups"])
                    groups=fake_group..","..groups
                    request_handle:headers():add("groups",groups)
                else
                    request_handle:headers():add("groups",array_to_string(value["groups"]))
                end
                request_handle:headers():add("roles",array_to_string(value["roles"]))
            else
                request_handle:headers():add(key,string.format("%s", value))
            end
        end
    end
end

return rolesinheaders

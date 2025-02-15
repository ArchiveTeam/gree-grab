dofile("table_show.lua")
dofile("urlcode.lua")
dofile("strict.lua")
local urlparse = require("socket.url")
local luasocket = require("socket") -- Used to get sub-second time
local http = require("socket.http")
JSON = assert(loadfile "JSON.lua")()

local item_name_newline = os.getenv("item_name_newline")
local start_urls = JSON:decode(os.getenv("start_urls"))
local items_table = JSON:decode(os.getenv("item_names_table"))
local item_dir = os.getenv("item_dir")
local warc_file_base = os.getenv("warc_file_base")

local url_count = 0
local tries = 0
local downloaded = {}
local addedtolist = {}
local abortgrab = false

local discovered_items = {}
local outlinks = {}

local last_main_site_time = 0
local current_item_type = nil
local current_item_value = nil
local next_start_url_index = 1

local callbackIndex = 0
local callbackOriginParmas = {}
local callbackOriginatingPages = {}

local targeted_regex_prefix = nil

io.stdout:setvbuf("no") -- So prints are not buffered - http://lua.2524044.n2.nabble.com/print-stdout-and-flush-td6406981.html

if urlparse == nil or http == nil then
  io.stdout:write("socket not corrently installed.\n")
  io.stdout:flush()
  abortgrab = true
end

do_debug = false
print_debug = function(a)
  if do_debug then
    print(a)
  end
end
print_debug("This grab script is running in debug mode. You should not see this in production.")

local start_urls_inverted = {}
for _, v in pairs(start_urls) do
  start_urls_inverted[v] = true
end

set_new_item = function(url)
  if url == start_urls[next_start_url_index] then
    current_item_type = items_table[next_start_url_index][1]
    current_item_value = items_table[next_start_url_index][2]
    next_start_url_index = next_start_url_index + 1
    print_debug("Setting CIT to " .. current_item_type)
    print_debug("Setting CIV to " .. current_item_value)

    if current_item_type == "user" then
      targeted_regex_prefix = "^https?://gree.jp/" .. current_item_value:gsub("%-", "%%-"):gsub("%.", "%%.")
      print_debug("TRP is " .. targeted_regex_prefix)
      assert(not string.match(current_item_value, "[^a-z0-9%-%_%.]"))
    else
      error("Add this item type to SNI")
    end
  end
  assert(current_item_type)
  assert(current_item_value)
end

discover_item = function(item_type, item_name)
  assert(item_type)
  assert(item_name)
  if not discovered_items[item_type .. ":" .. item_name] then
    print_debug("Queuing for discovery " .. item_type .. ":" .. item_name)
  end
  discovered_items[item_type .. ":" .. item_name] = true
end

add_ignore = function(url)
  if url == nil then -- For recursion
    return
  end
  if downloaded[url] ~= true then
    downloaded[url] = true
  else
    return
  end
  add_ignore(string.gsub(url, "^https", "http", 1))
  add_ignore(string.gsub(url, "^http:", "https:", 1))
  add_ignore(string.match(url, "^ +([^ ]+)"))
  add_ignore(string.match(url, "^(.+)/$"))
end

for ignore in io.open("ignore-list", "r"):lines() do
  add_ignore(ignore)
end

read_file = function(file)
  if file then
    local f = assert(io.open(file))
    local data = f:read("*all")
    f:close()
    return data
  else
    return ""
  end
end

is_on_targeted = function(url)
  if current_item_type == "user" then
    return string.match(url, targeted_regex_prefix .. "/")
      or string.match(url, targeted_regex_prefix .. "$")
  else
    error("You need to implement is_on_targeted for this item type")
  end
end

allowed = function(url, parenturl)
  --print_debug("Checking " .. url)

  if start_urls_inverted[url] then
    return false
  end

  local tested = {}
  for s in string.gmatch(url, "([^/]+)") do
    if tested[s] == nil then
      tested[s] = 0
    end
    if tested[s] == 6 then
      return false
    end
    tested[s] = tested[s] + 1
  end

  -- 3rd party sites, unnecess
  if string.match(url, "^https?://[^/]%.nitropay%.com/") then
    return false
  end

  -- Common resources and junk
  if string.match(url, "^https?://i%.gree%.jp/js/")
    or string.match(url, "^https?://i%.gree%.jp/img/skin")
    or string.match(url, "^https?://i%.gree%.jp/img/gree/")
    or string.match(url, "^https?://i%.gree%.jp/[^/]+$") then
    return false
  end

  -- Images
  if string.match(url, "^https?://[^/%.]+%.storage%.gree%.jp/")
    or string.match(url, "^https?://i%.gree%.jp/")
    or string.match(url, "^https?://aimg%-life%.gree%.jp/")then
    return true
  end

  if current_item_type == "user" then
    local user = string.match(url, "^https?://gree%.jp/([a-zA-Z0-9_]+)")
    if user and user ~= current_item_value then
      discover_item("user", user)
      return false
    end
  end

  if not is_on_targeted(url) then
    if not string.match(url, "^https?://[^/]*gree%.jp")
      and not string.match(url, "^https?://[^/]*gree%.net") then
      outlinks[url] = true
    end
    return false
  end

  --print_debug("Allowed true on " .. url)
  return true

  --assert(false, "This segment should not be reachable")
end


wget.callbacks.download_child_p = function(urlpos, parent, depth, start_url_parsed, iri, verdict, reason)
  local url = urlpos["url"]["url"]
  --print_debug("DCP on " .. url)
  if downloaded[url] == true or addedtolist[url] == true then
    return false
  end
  if allowed(url, parent["url"]) then
    addedtolist[url] = true
    return true
  end

  return false
end

wget.callbacks.get_urls = function(file, url, is_css, iri)
  local urls = {}
  local html = nil

  downloaded[url] = true

  local function check(urla, force)
    assert(not force or force == true) -- Don't accidentally put something else for force
    local origurl = url
    local url = string.match(urla, "^([^#]+)")
    local url_ = string.match(url, "^(.-)%.?$")
    url_ = string.gsub(url_, "&amp;", "&")
    url_ = string.match(url_, "^(.-)%s*$")
    url_ = string.match(url_, "^(.-)%??$")
    url_ = string.match(url_, "^(.-)&?$")
    -- url_ = string.match(url_, "^(.-)/?$") # Breaks dl.
    if (downloaded[url_] ~= true and addedtolist[url_] ~= true)
      and (allowed(url_, origurl) or force) then
      table.insert(urls, { url=url_ })
      addedtolist[url_] = true
      addedtolist[url] = true
    end
  end

  local function checknewurl(newurl)
    -- Being caused to fail by a recursive call on "../"
    if not newurl then
      return
    end
    if string.match(newurl, "\\[uU]002[fF]") then
      return checknewurl(string.gsub(newurl, "\\[uU]002[fF]", "/"))
    end
    if string.match(newurl, "^https?:////") then
      check((string.gsub(newurl, ":////", "://")))
    elseif string.match(newurl, "^https?://") then
      check(newurl)
    elseif string.match(newurl, "^https?:\\/\\?/") then
      check((string.gsub(newurl, "\\", "")))
    elseif string.match(newurl, "^\\/") then
      checknewurl(string.gsub(newurl, "\\", ""))
    elseif string.match(newurl, "^//") then
      check(urlparse.absolute(url, newurl))
    elseif string.match(newurl, "^/") then
      check(urlparse.absolute(url, newurl))
    elseif string.match(newurl, "^%.%./") then
      if string.match(url, "^https?://[^/]+/[^/]+/") then
        check(urlparse.absolute(url, newurl))
      else
        checknewurl(string.match(newurl, "^%.%.(/.+)$"))
      end
    elseif string.match(newurl, "^%./") then
      check(urlparse.absolute(url, newurl))
    end
  end

  local function checknewshorturl(newurl)
    if string.match(newurl, "^%?") then
      check(urlparse.absolute(url, newurl))
    elseif not (string.match(newurl, "^https?:\\?/\\?//?/?")
      or string.match(newurl, "^[/\\]")
      or string.match(newurl, "^%./")
      or string.match(newurl, "^[jJ]ava[sS]cript:")
      or string.match(newurl, "^[mM]ail[tT]o:")
      or string.match(newurl, "^vine:")
      or string.match(newurl, "^android%-app:")
      or string.match(newurl, "^ios%-app:")
      or string.match(newurl, "^%${")) then
      check(urlparse.absolute(url, newurl))
    end
  end

  local function load_html()
    if html == nil then
      html = read_file(file)
    end
  end

  local find_least = function(s)
    -- \d{14}-\d{6}-\d{10}
    local least = nil
    for post_id in string.gmatch(s, "id=\"(%d%d%d%d%d%d%d%d%d%d%d%d%d%d%-%d%d%d%d%d%d%-%d+)\"") do
      if not least or post_id < least then
        least = post_id
      end
    end
    print_debug("Least is" .. least)
    return least
  end


  if current_item_type == "user" and status_code == 200 and string.match(url, targeted_regex_prefix .. "$") then
    load_html()
    user_id = string.match(html, "user_id=(%d+)")
    assert(string.match(html, " u" .. user_id .. "\""))

    local least = find_least(html)
    if least then
      check("http://gree.jp/?action=api_stream_list&user_id=" .. user_id .. "&stream_id=stream_profile&start_key=" .. least .. "&offset=1", true)
    end
  end

  if current_item_type == "user" and status_code == 200 and string.match(url, "^https?://gree%.jp/%?action=api_stream_list") then
    load_html()
    body = JSON:decode(html)["html"]
    if body ~= "" then -- Else it has ended
      local least = find_least(body)
      if least then
        check("http://gree.jp/?action=api_stream_list&user_id=" .. user_id .. "&stream_id=stream_profile&start_key=" .. least .. "&offset=1", true)
      end
      for url in string.gmatch(body, '"(http.-)"') do
        print_debug("Checking " .. url .. " from body")
        check(url)
      end
      html = ""
    end
  end

  if status_code == 200 and not (string.match(url, "%.jpe?g$") or string.match(url, "%.png$"))
  and not string.match(url, "^https?://i%.gree%.jp/") then
    load_html()

    --[[for newurl in string.gmatch(string.gsub(html, "&quot;", '"'), '([^"]+)') do
      checknewurl(newurl)
    end
    for newurl in string.gmatch(string.gsub(html, "&#039;", "'"), "([^']+)") do
      checknewurl(newurl)
    end]] -- Extracting junk as usual
    for newurl in string.gmatch(html, ">%s*([^<%s]+)") do
      checknewurl(newurl)
    end
    for newurl in string.gmatch(html, "[^%-]href='([^']+)'") do
      checknewshorturl(newurl)
    end
    for newurl in string.gmatch(html, '[^%-]href="([^"]+)"') do
      checknewshorturl(newurl)
    end
    for newurl in string.gmatch(html, ":%s*url%(([^%)]+)%)") do
      checknewurl(newurl)
    end
  end

  return urls
end

wget.callbacks.httploop_result = function(url, err, http_stat)
  status_code = http_stat["statcode"]

  url_count = url_count + 1
  io.stdout:write(url_count .. "=" .. status_code .. " " .. url["url"] .. "  \n")
  io.stdout:flush()


  if status_code >= 300 and status_code <= 399 then
    local newloc = urlparse.absolute(url["url"], http_stat["newloc"])
    if downloaded[newloc] == true or addedtolist[newloc] == true
      or not allowed(newloc, url["url"]) then
      tries = 0
      return wget.actions.EXIT
    end
  end

  if status_code >= 200 and status_code <= 399 then
    downloaded[url["url"]] = true
  end

  if abortgrab == true then
    io.stdout:write("ABORTING...\n")
    io.stdout:flush()
    return wget.actions.ABORT
  end

  if status_code == 0
    or (status_code >= 400 and status_code ~= 404) then
    io.stdout:write("Server returned " .. http_stat.statcode .. " (" .. err .. "). Sleeping.\n")
    io.stdout:flush()
    local maxtries = 1
    if not allowed(url["url"], nil) then
      maxtries = 3
    end
    if tries >= maxtries then
      io.stdout:write("I give up...\n")
      io.stdout:flush()
      tries = 0
      abort_item()
      return wget.actions.ABORT
    else
      os.execute("sleep " .. math.floor(math.pow(2, tries)))
      tries = tries + 1
      return wget.actions.CONTINUE
    end
  end

  tries = 0

  local sleep_time = 0

  if sleep_time > 0.001 then
    os.execute("sleep " .. sleep_time)
  end

  return wget.actions.NOTHING
end


queue_list_to = function(list, key)
  if do_debug then
    for item, _ in pairs(list) do
      print("Would have sent discovered item " .. item)
    end
  else
    local to_send = nil
    for item, _ in pairs(list) do
      assert(string.match(item, ":")) -- Message from EggplantN, #binnedtray (search "colon"?)
      if to_send == nil then
        to_send = item
      else
        to_send = to_send .. "\0" .. item
      end
      print("Queued " .. item)
    end

    if to_send ~= nil then
      local tries = 0
      while tries < 10 do
        local body, code, headers, status = http.request(
          "http://blackbird-amqp.meo.ws:23038/" .. key .. "/",
          to_send
        )
        if code == 200 or code == 409 then
          break
        end
        os.execute("sleep " .. math.floor(math.pow(2, tries)))
        tries = tries + 1
      end
      if tries == 10 then
        abortgrab = true
      end
    end
  end
end


wget.callbacks.finish = function(start_time, end_time, wall_time, numurls, total_downloaded_bytes, total_download_time)
  queue_list_to(discovered_items, "gree2-emxewc7kf772wfq")
  queue_list_to(outlinks, "urls-zvn3fnnvby65mhc")
end

wget.callbacks.write_to_warc = function(url, http_stat)
  set_new_item(url["url"])
  return true
end

wget.callbacks.before_exit = function(exit_status, exit_status_string)
  if abortgrab == true then
    return wget.exits.IO_FAIL
  end
  return exit_status
end


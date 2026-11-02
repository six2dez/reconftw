# Metadata only: never propagate leak bodies, leak-site links or credentials.
def text: if type == "string" then gsub("[[:space:]]+"; " ") elif type == "number" then tostring else "" end;
def record($product; $category):
  {product: $product, category: $category,
   id: ((.victim_id // .id_source // .id) | text),
   title: ((.post_title // .name // .website) | text),
   website: (.website | text), group: (.group_name | text),
   country: (.country | text), discovered: ((.discovered | text)[0:10])};
def matches($domain):
  (.website | ascii_downcase | rtrimstr(".")) as $site |
  if $site != "" then $site == $domain or ($site | endswith("." + $domain))
  else (.title | ascii_downcase | test("(?<![a-z0-9_-])" + ($domain | gsub("\\."; "\\.")) + "(?![a-z0-9_-]|\\.[a-z0-9_])")) end;
if $product == "HaveIBeenRansom" then
  if type != "object" or ((.sources // .results) | type) != "array" then error("Invalid metadata response") else
    {records: [(.sources // .results)[] | select(type == "object") |
      record($product; if .leak_type == "ransomware_leak" then "ransomware"
        elif .leak_type == "traditional_breach" then "breach" else (.leak_type // "leak" | text) end)],
     has_next: ((if has("has_next") then .has_next else (.pagination.has_next // false) end) == true)}
  end
else
  if type != "object" or ([.ransomware, .breaches, .leads, .stealers] | all(. == null)) then error("Invalid search response") else
    . as $data |
    ["ransomware", "breaches", "leads", "stealers"] |
    map(. as $source | ($data[$source] // []) as $section |
      (if $section | type == "array" then $section else $section.results end) as $items |
      if ($items | type) != "array" then error("Invalid search section") else
        {records: [$items[] | select(type == "object") |
          record($product; if $source == "breaches" then "breach" elif $source == "stealers" then "stealer" else $source end) |
          select(matches($domain))],
         truncated: (($items | length) >= $limit or
           (if $section | type == "object" then (($section.total // 0) > ($items | length)) else false end))}
      end) |
    {records: [.[].records[]], has_next: any(.truncated)}
  end
end

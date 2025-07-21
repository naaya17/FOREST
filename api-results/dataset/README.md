# Internal API Endpoints Detected by FOREST  
**Service:** Mattermost  
**Versions Compared:**  
- Mattermost 3.7.0 (API v3)
- Mattermost 10.6.1 (API v4)

(To protect personal information, the datasets from Microsoft OneDrive and Microsoft Teams were not uploaded.)

### Endpoints Not Included in Detection Results

During the analysis of Mattermost 3.7.0 and 10.6.1, FOREST was unable to detect certain endpoints. This was because the responses collected during testing did not provide sufficient forensic significance to warrant detection. However, it was confirmed that this behavior can be adjusted using AI prompts or by configuring the temperature parameter in the GPT API.

---

#### 📌 Examples from Mattermost 3.7.0

- `binary file` (starts with `%PDF-1.4...`)
- `{"channel_id":"pc4mi6g747dh8j4dc4yf4ijkho","member_count":2}`
- `[]`
- `{}`
- `{"fp61si75ftg1xrit7ghqkmtubo":"offline"}`

---

#### 📌 Examples from Mattermost 10.6.1

- `{"status":"OK","last_viewed_at_times":{"zris48c67tnkiq9dkg6xxh8ico":1742539732630}}`
- `{"694krauqnb8m5qdyzw91fszcra":5,"m1gi99dqjifhde81jf4pywu3we":5,"m44gs5os5in37kerkx7eaazfke":2,"zris48c67tnkiq9dkg6xxh8ico":2}`
- `{"total":0,"total_unread_threads":0,"total_unread_mentions":0,"total_unread_urgent_mentions":0,"threads":null}`
- `{"id":"4xpnr98ydfd3tgizugeogtqbah","create_at":1742465680203,"update_at":1742465680203,"delete_at":0,"team_id":"","type":"D","display_name":"","name":"541udeka77grmxb4bmssfgqxty__mgoxgooa6if8bps5psjykm4w8e","header":"","purpose":"","last_post_at":0,"total_msg_count":0,"extra_update_at":0,"creator_id":"541udeka77grmxb4bmssfgqxty","scheme_id":null,"props":null,"group_constrained":null,"shared":false,"total_msg_count_root":0,"policy_id":null,"last_root_post_at":0}`
- `{"total_users_count":9}`

---

## ✅ Detected Endpoints in Mattermost 3.7.0

| No. | Endpoint                                                                                                       | Available |
|-----|----------------------------------------------------------------------------------------------------------------|-----------|
| 1   | http://127.0.0.1:8065/api/v3/files/{file_id}/get                                                               | ❌        |
| 2   | http://127.0.0.1:8065/api/v3/files/{file_id}/get_public_link                                                   | ❌        |
| 3   | http://127.0.0.1:8065/api/v3/teams/{team_id}/channels/{channel_id}/members/{user_id}                          | ✅        |
| 4   | http://127.0.0.1:8065/api/v3/teams/{team_id}/channels/{channel_id}/posts/page/0/60                            | ✅        |
| 5   | http://127.0.0.1:8065/api/v3/teams/{team_id}/channels/{channel_id}/stats                                      | ✅        |
| 6   | http://127.0.0.1:8065/api/v3/teams/{team_id}/channels/members                                                 | ✅        |
| 7   | http://127.0.0.1:8065/api/v3/teams/{team_id}/channels/more/0/100                                              | ❌        |
| 8   | http://127.0.0.1:8065/api/v3/teams/{team_id}/members/ids                                                      | ✅        |
| 9   | http://127.0.0.1:8065/api/v3/teams/{team_id}/stats                                                             | ✅        |
| 10  | http://127.0.0.1:8065/api/v3/teams/{team_id}/users/0/100                                                      | ✅        |
| 11  | http://127.0.0.1:8065/api/v3/teams/{team_id}channels/{channel_id}/posts/{post_id}/get_file_infos              | ✅        |
| 12  | http://127.0.0.1:8065/api/v3/teams/all_team_listings                                                           | ❌        |
| 13  | http://127.0.0.1:8065/api/v3/users/0/100                                                                       | ✅        |
| 14  | http://127.0.0.1:8065/api/v3/users/ids                                                                         | ✅        |
| 15  | http://127.0.0.1:8065/api/v3/users/initial_load                                                                | ✅        |
| 16  | http://127.0.0.1:8065/api/v3/users/login                                                                       | ✅        |
| 17  | http://127.0.0.1:8065/api/v3/users/status/ids                                                                  | ❌        |

---

## ✅ Detected Endpoints in Mattermost 10.6.1

| No. | Endpoint                                                                                     | Available |
|-----|----------------------------------------------------------------------------------------------|-----------|
| 1   | http://127.0.0.1:9065/api/v4/channels/{channel_id}/members/ids                               | ✅        |
| 2   | http://127.0.0.1:9065/api/v4/channels/{channel_id}/members/me                                | ✅        |
| 3   | http://127.0.0.1:9065/api/v4/channels/{channel_id}/posts                                     | ✅        |
| 4   | http://127.0.0.1:9065/api/v4/channels/members/me/view                                        | ❌        |
| 5   | http://127.0.0.1:9065/api/v4/channels/stats/member_count                                     | ❌        |
| 6   | http://127.0.0.1:9065/api/v4/channels/{channel_id}/stats                                     | ✅        |
| 7   | http://127.0.0.1:9065/api/v4/posts/{id}/info                                                 | ✅        |
| 8   | http://127.0.0.1:9065/api/v4/posts/{id}/thread                                               | ✅        |
| 9   | http://127.0.0.1:9065/api/v4/teams                                                           | ✅        |
| 10  | http://127.0.0.1:9065/api/v4/teams/{team_id}/channels                                        | ✅        |
| 11  | http://127.0.0.1:9065/api/v4/teams/{team_id}/files/search                                    | ✅        |
| 12  | http://127.0.0.1:9065/api/v4/teams/{team_id}/posts/search                                    | ✅        |
| 13  | http://127.0.0.1:9065/api/v4/users                                                           | ✅        |
| 14  | http://127.0.0.1:9065/api/v4/users/{user_id}/channel_members                                 | ✅        |
| 15  | http://127.0.0.1:9065/api/v4/users/{user_id}/channels/{channel_id}/posts/unread              | ✅        |
| 16  | http://127.0.0.1:9065/api/v4/users/{user_id}/teams/{team_id}/channels/categories             | ✅        |
| 17  | http://127.0.0.1:9065/api/v4/users/{user_id}/teams/{team_id}/threads                         | ❌        |
| 18  | http://127.0.0.1:9065/api/v4/users/autocomplete                                              | ✅        |
| 19  | http://127.0.0.1:9065/api/v4/users/ids                                                       | ✅        |
| 20  | http://127.0.0.1:9065/api/v4/users/login                                                     | ✅        |
| 21  | http://127.0.0.1:9065/api/v4/users/me                                                        | ✅        |
| 22  | http://127.0.0.1:9065/api/v4/users/me/channels                                               | ❌        |
| 23  | http://127.0.0.1:9065/api/v4/users/me/preferences                                            | ✅        |
| 24  | http://127.0.0.1:9065/api/v4/users/me/teams                                                  | ✅        |
| 25  | http://127.0.0.1:9065/api/v4/users/me/teams/{team_id}/channels                               | ✅        |
| 26  | http://127.0.0.1:9065/api/v4/users/me/teams/{team_id}/channels/members                       | ✅        |
| 27  | http://127.0.0.1:9065/api/v4/users/me/teams/members                                          | ✅        |
| 28  | http://127.0.0.1:9065/api/v4/users/me/teams/unread                                           | ✅        |
| 29  | http://127.0.0.1:9065/api/v4/users/stats                                                     | ❌        |
| 30  | http://127.0.0.1:9065/api/v4/users/status/ids                                                | ✅        |

---

**Note:** All endpoints were passively and automatically extracted through forensic traffic analysis. `✅` indicates that the endpoint was accessible at the time of testing, while `❌` indicates it was not.

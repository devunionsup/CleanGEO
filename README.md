# CleanGEO

iOS აპი ქართული ვების გასასუფთავებლად: Safari Content Blocker + ლოკალური VPN (Packet Tunnel) DNS-ფილტრაციით, DoH ჯაჭვით და ქართული ინტერფეისით.

## არქიტექტურა
| კომპონენტი | სტატუსი |
|---|---|
| SwiftUI + WebKit ჰიბრიდი (InterfaceBridge, სიგნატურით push) | ✔ |
| Safari Content Blocker (FilterCompiler → blocker JSON) | ✔ |
| ლოკალური Packet Tunnel (DNS ტუნელი, 0.0.0.0 პასუხი, DoH) | ✔ |
| DoH (RFC 8484) ჯაჭვით + ავტო-fallback | ✔ |
| FilterListManager (BGTask, 6 სთ) | ✔ |
| DNSSECValidator | phase 2 |
| RecursiveResolver | phase 2 |
| DoT (RFC 7858) | phase 2 |
| განრიგი (4 სლოტი) | phase 2 |

## იდენტიფიკატორები (არ შეიცვალოს)
- აპი: `DEV.GIORGI.DEV`
- Safari გაფართოება: `DEV.GIORGI.DEV.BlockerExtension`
- VPN გაფართოება: `DEV.GIORGI.DEV.VPN`
- BGTask: `DEV.GIORGI.DEV.refresh`
- App Group: `group.87486bbbb00f533a.3`

## CI
`.github/workflows/build.yml` — XcodeGen → ტესტები → unsigned archive → release `build-<run_number>`. IPA შეიცავს ორივე გაფართოებას (PlugIns/).

## ფილტრები
- ჩაშენებული: `CleanGEO/CleanGEO/Resources/CleanGEO.txt`
- დამატებითი: მხოლოდ https-სიები აპიდან.

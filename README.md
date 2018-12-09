# wildcert
LetsEncrypt wildcard certificate auto-renew

- config
>Setup your conoha api informations.
>```json
>{
>	"user": "[tenant name]",
>	"passwd": "[api password]",
>	"tenant": "[tenant id]"
>}
>```

- wildcert.py
>python wildcert.py -d [domain]
>That's it
>add /etc/cron.d/certbot
>```sh
>0 */12 * * * root test -x /usr/bin/certbot -a \! -d /run/systemd/system && perl -e 'sleep int(rand(43200))' && python [wildcert path]/wildcert.py -d [domain]
>```

# Déploiement Kubernetes

```sh
# 1. image
docker build -t REGISTRY/ubproxy:1.0.0 ..      # depuis ublock-proxy/
docker push REGISTRY/ubproxy:1.0.0

# 2. manifestes (remplacer REGISTRY et l'IP MetalLB au préalable)
kubectl apply -f configmap.yaml -f pvc.yaml -f deployment.yaml -f service.yaml
kubectl rollout status deploy/ubproxy
kubectl logs deploy/ubproxy | tail        # doit afficher "filter engine ready"
```

Le premier démarrage télécharge les listes : comptez une minute avant que le
pod soit prêt (`startupProbe` prévue pour). Les nœuds doivent donc pouvoir
joindre `easylist.to` et `ublockorigin.github.io` ; sinon, montez les listes
dans le ConfigMap et pointez `lists` sur des chemins locaux.

## Brancher un client

Récupérer l'IP du service, puis la renseigner comme proxy HTTP/HTTPS sur le
client (iPhone : *Réglages → Wi-Fi → (i) → Configurer le proxy → Manuel*) :

```sh
kubectl get svc ubproxy -o jsonpath='{.status.loadBalancer.ingress[0].ip}'
```

Sans LoadBalancer, passez le Service en `NodePort` et visez
`<ip-du-nœud>:<nodePort>`. Pour un essai rapide sans exposition :

```sh
kubectl port-forward svc/ubproxy 8080:8080
curl -x http://127.0.0.1:8080 http://exemple.test/
```

## Certificat (seulement si `mitm = true`)

Le pod sert lui-même sa CA sur son port HTTP : ouvrez
`http://<ip-du-service>:8080/` dans le navigateur du client, la page propose le
téléchargement et rappelle les étapes d'installation. Pensez à garder le PVC :
c'est lui qui conserve la CA entre deux redémarrages.

## Ce que le cluster ne peut pas faire

Le mode transparent (redirection netfilter, sans réglage sur le client) suppose
que le trafic du client **traverse** la machine qui filtre. Un nœud Kubernetes
n'est généralement pas la passerelle du réseau : dans ce cas seul le mode proxy
explicite fonctionne, ou alors il faut faire aboutir un tunnel (WireGuard) sur
le nœud. `daemonset-transparent.yaml` couvre ce second cas.

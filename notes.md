## Possible extensions

### Robustness and Security
- Gennaro et al. improve on the Ped-DKG and propose a [more robust version called New-DKG](https://link.springer.com/article/10.1007/s00145-006-0347-3).
- Canetti et al. extend New-DKG to make it [secure against adaptive adversaries](https://link.springer.com/content/pdf/10.1007/3-540-48405-1_7.pdf).
- Jarecki and Lysyanskaya present the [erasure-free model](https://www.iacr.org/archive/eurocrypt2000/1807/18070223-new.pdf) for threshold schemes secure against adaptive adversaries.

### Secret share update without impact on the long term secret-public key pair
- Herzberg et al. propose [Proactive Secret Sharing](https://www.researchgate.net/profile/Amir-Herzberg/publication/221355399_Proactive_Secret_Sharing_Or_How_to_Cope_With_Perpetual_Leakage/links/02e7e52e0ecf4dbae1000000/Proactive-Secret-Sharing-Or-How-to-Cope-With-Perpetual-Leakage.pdf), allowing for shares to be rotated without impact on the secret key.

### Key share reconstruction
- Laing and Stinson [refine Repairable Threshold Schemes](https://eprint.iacr.org/2017/1155.pdf) to enable a participant to securely reconstruct a lost share with help from their peers.

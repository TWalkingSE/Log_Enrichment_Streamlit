"""analysis.comms — split from analysis monolith."""
import pandas as pd
import logging

logger = logging.getLogger(__name__)

def detect_disposable_numbers(df, from_col='FROM', date_col='Data', min_appearances=1, max_appearances=3):
    """
    Detect contacts that appear very few times (potentially disposable numbers).

    Returns DataFrame with suspicious numbers.
    """
    if from_col not in df.columns:
        return pd.DataFrame(columns=['Numero', 'Aparicoes', 'Primeiro_Contato', 'Ultimo_Contato', 'Duracao_Dias'])

    counts = df[from_col].value_counts()
    suspicious = counts[(counts >= min_appearances) & (counts <= max_appearances)]

    if suspicious.empty:
        return pd.DataFrame(columns=['Numero', 'Aparicoes', 'Primeiro_Contato', 'Ultimo_Contato', 'Duracao_Dias'])

    rows = []
    for number, count in suspicious.items():
        if not number or str(number).strip() == '':
            continue
        subset = df[df[from_col] == number]

        first = ''
        last = ''
        duration = 0
        if date_col in subset.columns:
            dates = pd.to_datetime(subset[date_col], errors='coerce').dropna()
            if not dates.empty:
                first = dates.min().strftime('%Y-%m-%d %H:%M')
                last = dates.max().strftime('%Y-%m-%d %H:%M')
                duration = (dates.max() - dates.min()).days

        types = ', '.join(subset['type'].unique().tolist()) if 'type' in subset.columns else ''

        rows.append({
            'Numero': number,
            'Aparicoes': count,
            'Primeiro_Contato': first,
            'Ultimo_Contato': last,
            'Duracao_Dias': duration,
            'Tipos': types
        })

    return pd.DataFrame(rows).sort_values('Aparicoes')



# src/visualization/wordcloud_viz.py
from wordcloud import WordCloud
import matplotlib.pyplot as plt
from collections import Counter

class AttackWordCloud:
    """Generate word clouds from attack patterns"""
    
    def create_attack_wordcloud(self, alerts):
        """Create word cloud from attack types and IPs"""
        if not alerts:
            return
        
        # Combine attack types and source IPs
        text_parts = []
        for alert in alerts:
            text_parts.append(alert['attack_type'] * int(alert['confidence'] * 10))
            text_parts.append(alert['source_ip'].split('.')[-1] * 3)
        
        text = ' '.join(text_parts)
        
        # Generate word cloud
        wordcloud = WordCloud(
            width=800, height=400,
            background_color='white',
            colormap='Reds',
            max_words=50
        ).generate(text)
        
        fig, ax = plt.subplots(figsize=(10, 5))
        ax.imshow(wordcloud, interpolation='bilinear')
        ax.axis('off')
        ax.set_title("Threat Intelligence Word Cloud", fontsize=16, fontweight='bold')
        
        st.pyplot(fig)

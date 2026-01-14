import streamlit as st
import pandas as pd
import plotly.express as px # 建議安裝：pip install plotly (用於更美觀的互動式圖表)
import re

# --- UI 佈局設定 ---
st.set_page_config(page_title="Darktrace NDR 自動化分析報告", layout="wide")

# 自定義 CSS 讓報告看起來更專業
st.markdown("""
    <style>
    .main { background-color: #f5f7f9; }
    .stMetric { background-color: #ffffff; padding: 15px; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
    </style>
    """, unsafe_allow_html=True)

# --- 模擬解析邏輯 (根據您的 Agenda 大綱) ---
def parse_darktrace_data(raw_text):
    """
    從 PDF 或文字中提取關鍵資訊的逻辑。
    實作時需根據實際報告的 Regex 進行微調。
    """
    results = {}
    
    # 1. 搜尋 DGA / C2 事件 (Regex 範例)
    results['dga_events'] = len(re.findall(r"DGA DNS|Detected DGA", raw_text, re.I))
    results['c2_events'] = len(re.findall(r"C2/CC|Command and Control", raw_text, re.I))
    
    # 2. 模擬提取 Top 裝置數據 (實作時應從 Table 提取)
    # 這裡建立範例 DataFrame 供視覺化展示
    results['top_devices_df'] = pd.DataFrame({
        'Device': ['Server-AD-01', 'Workstation-102', 'IoT-Camera-05', 'CEO-Laptop', 'HR-PC-02'],
        'Score': [95, 88, 76, 65, 42]
    })
    
    # 3. 模擬攻擊階段占比
    results['attack_phases'] = pd.DataFrame({
        'Phase': ['Reconnaissance', 'Lateral Movement', 'C&C', 'Exfiltration', 'Compliance'],
        'Count': [12, 8, 5, 2, 20]
    })
    
    return results

# --- 主程式介面 ---
st.title("🛡️ Darktrace NDR 自動化分析戰情室")
st.caption("自動化產出：資安事件統計、佈署狀態與根因分析報告")

# 側邊欄：上傳與參數設定
with st.sidebar:
    st.header("⚙️ 報告設定")
    uploaded_file = st.sidebar.file_uploader("上傳 Darktrace 原始檔案", type=["pdf", "json", "csv", "txt"])
    report_date = st.date_input("報告產出日期")
    st.divider()
    st.info("本系統會自動解析 Cyber AI Insight 與 AI Analyst 數據。")

if uploaded_file:
    # 這裡調用您之前寫的 load_data 函數 (假設已讀取為 text)
    # raw_content, data_type = load_data(uploaded_file)
    # analysis = parse_darktrace_data(str(raw_content))
    
    # 模擬數據 (實際運行時請替換為分析後的 results)
    analysis = parse_darktrace_data("") 

    # --- 導航分頁 (對應您的 Agenda) ---
    tab1, tab2, tab3 = st.tabs(["🌐 1. 佈署監控狀態", "📊 2. Summary 資安事件", "🧠 3. 攻擊階段 & RCA"])

    # --- 分頁 1: 佈署監控系統狀態 ---
    with tab1:
        st.subheader("Deployment Overview")
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("佈署模式", "Physical Appliance")
        col2.metric("監控網段", "18 Subnets")
        col3.metric("CPU 使用率", "24%", "-2%")
        col4.metric("系統狀態", "Running", delta="Normal")
        
        st.info("🔍 **監控資源詳情：** 當前流量吞吐量峰值為 1.2 Gbps，所有 Sensor 連線狀態正常。")

    # --- 分頁 2: Summary 資安事件 ---
    with tab2:
        st.subheader("事件摘要與高風險裝置")
        
        c1, c2 = st.columns([1, 1])
        with c1:
            st.write("📌 **觸發高風險事件之 Device (Top 5)**")
            fig_devices = px.bar(analysis['top_devices_df'], x='Score', y='Device', orientation='h', 
                                 color='Score', color_continuous_scale='Reds')
            st.plotly_chart(fig_devices, use_container_width=True)
            
        with c2:
            st.write("📌 **觸發違規模型 Categories 占比**")
            fig_pie = px.pie(analysis['attack_phases'], values='Count', names='Phase', hole=0.4)
            st.plotly_chart(fig_pie, use_container_width=True)

        st.subheader("事件列表預覽 (Incidents List)")
        st.table(analysis['top_devices_df']) # 這裡應改為顯示真正的 Incident 列表

    # --- 分頁 3: 攻擊階段事件分析 & RCA ---
    with tab3:
        st.subheader("Cyber AI Insight: 根因分析報告")
        
        # Incident Report - Host 專區
        with st.expander("📡 DNS 與 C2/CC 深度調查 (Incident Report - Host)", expanded=True):
            col_l, col_r = st.columns(2)
            with col_l:
                st.error(f"Detected DGA DNS queries: {analysis['dga_events']} 件")
                st.warning(f"Resolving Fluxing DNS queries: 3 件")
            with col_r:
                st.write("**AI Analyst 分析建議：**")
                st.write("- 偵測到內部主機出現異常 DGA 查詢，推測為惡意程式嘗試聯繫 C2。")
                st.write("- 建議優先檢查 `Server-AD-01` 的外對連線紀錄。")

        # 顯示攻擊階段
        st.subheader("AI Analyst Incident Event Phases")
        
        st.write("當前偵測到的威脅主要集中在 **'Action on Objectives'** 與 **'C&C'** 階段，顯示威脅已進入後期。")

        # 自動生成總結
        st.subheader("📝 自動化分析總結")
        st.success(f"""
        1. **高風險設備**: 本次分析共發現 {len(analysis['top_devices_df'])} 個高風險裝置，其中以 {analysis['top_devices_df'].iloc[0]['Device']} 最為嚴重。
        2. **主要攻擊類型**: 偵測到顯著的 DGA DNS 行為，符合 C2/CC 攻擊特徵。
        3. **合規性**: 觸發合規模型之 Incidents 主要集中在非授權加密流量。
        """)

else:
    st.warning("👈 請在上傳區提供 Darktrace 報告文件 (PDF/JSON/CSV) 以產出分析。")
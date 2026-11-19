import SwiftUI

struct ConnectionSettingsPage: View {
    @State private var showingRules = false
    var preview: [ConnectionRow]? = nil

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text(showingRules ? "按需连接" : "当前连接").font(.headline)
                Spacer()
                Picker("连接内容", selection: $showingRules) {
                    Text("当前连接").tag(false)
                    Text("按需连接").tag(true)
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(width: 220)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
            Divider()
            if showingRules {
                Form { OnDemandSettings() }
                    .formStyle(.grouped)
            } else {
                ConnectionsPage(preview: preview)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

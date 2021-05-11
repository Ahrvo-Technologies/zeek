#include "zeek/packet_analysis/protocol/ip/AnalyzerAdapter.h"

#include "zeek/File.h"
#include "zeek/ZeekString.h"
#include "zeek/packet_analysis/protocol/ip/IPBasedAnalyzer.h"

using namespace zeek::packet_analysis::IP;

void AnalyzerAdapter::Done()
	{
	Analyzer::Done();
	}

bool AnalyzerAdapter::IsReuse(double t, const u_char* pkt)
	{
	return parent->IsReuse(t, pkt);
	}

void AnalyzerAdapter::SetContentsFile(unsigned int /* direction */,
                                             FilePtr /* f */)
	{
	reporter->Error("analyzer type does not support writing to a contents file");
	}

zeek::FilePtr AnalyzerAdapter::GetContentsFile(unsigned int /* direction */) const
	{
	reporter->Error("analyzer type does not support writing to a contents file");
	return nullptr;
	}

void AnalyzerAdapter::PacketContents(const u_char* data, int len)
	{
	if ( packet_contents && len > 0 )
		{
		zeek::String* cbs = new zeek::String(data, len, true);
		auto contents = make_intrusive<StringVal>(cbs);
		EnqueueConnEvent(packet_contents, ConnVal(), std::move(contents));
		}
	}
